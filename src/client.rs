use std::collections::HashMap;
use std::time::Duration;

use reqwest::header::{ACCEPT, CONTENT_TYPE, HeaderMap, HeaderValue};
use reqwest::{Client, Method, Response, StatusCode};
use serde_json::Value;
use url::Url;

use crate::error::{MispError, MispResult};
use crate::models::attribute::MispAttribute;
use crate::models::correlation::{MispCorrelationExclusion, MispDecayingModel};
use crate::models::event::MispEvent;
use crate::models::event_report::MispEventReport;
use crate::models::galaxy::{MispGalaxy, MispGalaxyCluster, MispGalaxyClusterRelation};
use crate::models::noticelist::MispNoticelist;
use crate::models::object::{MispObject, MispObjectReference, MispObjectTemplate};
use crate::models::shadow_attribute::MispShadowAttribute;
use crate::models::sighting::MispSighting;
use crate::models::tag::MispTag;
use crate::models::taxonomy::MispTaxonomy;
use crate::models::warninglist::MispWarninglist;

/// Async client for the MISP REST API.
///
/// Create via [`MispClient::new`] for simple usage, or
/// [`MispClient::builder`] for advanced configuration.
#[derive(Debug, Clone)]
pub struct MispClient {
    base_url: Url,
    #[allow(dead_code)] // Used in later iterations for key rotation
    api_key: String,
    client: Client,
}

/// Builder for constructing a [`MispClient`] with advanced options.
#[derive(Debug)]
pub struct MispClientBuilder {
    url: String,
    key: String,
    ssl_verify: bool,
    timeout: Option<Duration>,
    proxy: Option<String>,
    headers: HashMap<String, String>,
}

impl MispClientBuilder {
    fn new(url: impl Into<String>, key: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            key: key.into(),
            ssl_verify: true,
            timeout: None,
            proxy: None,
            headers: HashMap::new(),
        }
    }

    /// Disable TLS certificate verification.
    pub fn ssl_verify(mut self, verify: bool) -> Self {
        self.ssl_verify = verify;
        self
    }

    /// Set a request timeout.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Set an HTTP proxy URL.
    pub fn proxy(mut self, proxy: impl Into<String>) -> Self {
        self.proxy = Some(proxy.into());
        self
    }

    /// Add a custom header to all requests.
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(name.into(), value.into());
        self
    }

    /// Build the [`MispClient`].
    pub fn build(self) -> MispResult<MispClient> {
        let base_url = normalize_url(&self.url)?;

        let mut default_headers = HeaderMap::new();
        default_headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
        default_headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        default_headers.insert(
            "Authorization",
            HeaderValue::from_str(&self.key).map_err(|e| {
                MispError::InvalidInput(format!("Invalid API key header value: {e}"))
            })?,
        );
        for (k, v) in &self.headers {
            let name = reqwest::header::HeaderName::from_bytes(k.as_bytes())
                .map_err(|e| MispError::InvalidInput(format!("Invalid header name '{k}': {e}")))?;
            let val = HeaderValue::from_str(v)
                .map_err(|e| MispError::InvalidInput(format!("Invalid header value: {e}")))?;
            default_headers.insert(name, val);
        }

        let mut builder = Client::builder()
            .default_headers(default_headers)
            .danger_accept_invalid_certs(!self.ssl_verify);

        if let Some(timeout) = self.timeout {
            builder = builder.timeout(timeout);
        }

        if let Some(proxy_url) = &self.proxy {
            let proxy = reqwest::Proxy::all(proxy_url)
                .map_err(|e| MispError::InvalidInput(format!("Invalid proxy URL: {e}")))?;
            builder = builder.proxy(proxy);
        }

        let client = builder.build()?;

        Ok(MispClient {
            base_url,
            api_key: self.key,
            client,
        })
    }
}

impl MispClient {
    /// Create a new MISP client.
    ///
    /// # Arguments
    /// * `url` - Base URL of the MISP instance (e.g. `https://misp.example.com`)
    /// * `key` - MISP API key (automation key)
    /// * `ssl_verify` - Whether to verify TLS certificates
    pub fn new(
        url: impl Into<String>,
        key: impl Into<String>,
        ssl_verify: bool,
    ) -> MispResult<Self> {
        Self::builder(url, key).ssl_verify(ssl_verify).build()
    }

    /// Create a builder for advanced client configuration.
    pub fn builder(url: impl Into<String>, key: impl Into<String>) -> MispClientBuilder {
        MispClientBuilder::new(url, key)
    }

    /// Get the base URL of this client.
    pub fn base_url(&self) -> &Url {
        &self.base_url
    }

    // ── Internal request helpers ──────────────────────────────────────

    /// Prepare and send an HTTP request to the MISP API.
    async fn request(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
    ) -> MispResult<Response> {
        let url = self.base_url.join(path)?;
        log::debug!("{} {}", method, url);

        let mut req = self.client.request(method, url);
        if let Some(body) = body {
            req = req.json(body);
        }

        let response = req.send().await?;
        Ok(response)
    }

    /// Send a GET request and parse the JSON response.
    async fn get(&self, path: &str) -> MispResult<Value> {
        let response = self.request(Method::GET, path, None).await?;
        self.check_response(response).await
    }

    /// Send a POST request with a JSON body and parse the response.
    async fn post(&self, path: &str, body: &Value) -> MispResult<Value> {
        let response = self.request(Method::POST, path, Some(body)).await?;
        self.check_response(response).await
    }

    /// Send a HEAD request and return whether the resource exists (2xx).
    #[allow(dead_code)] // Used in later iterations for exists checks
    async fn head(&self, path: &str) -> MispResult<bool> {
        let response = self.request(Method::HEAD, path, None).await?;
        Ok(response.status().is_success())
    }

    /// Check an HTTP response for errors and parse the body as JSON.
    async fn check_response(&self, response: Response) -> MispResult<Value> {
        let status = response.status();

        if status == StatusCode::FORBIDDEN || status == StatusCode::UNAUTHORIZED {
            let text = response.text().await.unwrap_or_default();
            return Err(MispError::AuthError(format!(
                "HTTP {}: {}",
                status.as_u16(),
                text
            )));
        }

        if status == StatusCode::NOT_FOUND {
            let text = response.text().await.unwrap_or_default();
            return Err(MispError::NotFound(text));
        }

        if !status.is_success() {
            let code = status.as_u16();
            let text = response.text().await.unwrap_or_default();
            // Try to extract a message from the JSON body
            if let Ok(json) = serde_json::from_str::<Value>(&text) {
                let message = json["message"]
                    .as_str()
                    .or_else(|| json["errors"].as_str())
                    .unwrap_or(&text)
                    .to_string();
                return Err(MispError::ApiError {
                    status: code,
                    message,
                });
            }
            return Err(MispError::ApiError {
                status: code,
                message: text,
            });
        }

        let body = response.text().await?;
        let json: Value = serde_json::from_str(&body)?;
        Ok(json)
    }

    // ── Server / Instance Info ────────────────────────────────────────

    /// Load `describeTypes` from the bundled JSON file.
    pub fn describe_types_local(&self) -> MispResult<Value> {
        let data = include_str!("../data/describeTypes.json");
        let json: Value = serde_json::from_str(data)?;
        Ok(json)
    }

    /// Fetch `describeTypes` from the remote MISP instance.
    pub async fn describe_types_remote(&self) -> MispResult<Value> {
        self.get("attributes/describeTypes.json").await
    }

    /// Get the MISP instance version.
    pub async fn misp_instance_version(&self) -> MispResult<Value> {
        self.get("servers/getVersion").await
    }

    /// Get the recommended PyMISP version for this MISP instance.
    pub async fn version(&self) -> MispResult<Value> {
        self.get("servers/getPyMISPVersion.json").await
    }

    /// Get all server settings.
    pub async fn server_settings(&self) -> MispResult<Value> {
        self.get("servers/serverSettings").await
    }

    /// Get a specific server setting.
    pub async fn get_server_setting(&self, setting: &str) -> MispResult<Value> {
        self.get(&format!("servers/getSetting/{setting}")).await
    }

    /// Set a specific server setting.
    pub async fn set_server_setting(
        &self,
        setting: &str,
        value: impl Into<Value>,
    ) -> MispResult<Value> {
        let body = serde_json::json!({ "value": value.into() });
        self.post(&format!("servers/serverSettingsEdit/{setting}"), &body)
            .await
    }

    /// Query the ACL system for debugging.
    pub async fn remote_acl(&self, debug_type: Option<&str>) -> MispResult<Value> {
        let path = match debug_type {
            Some(dt) => format!("servers/queryACL/{dt}"),
            None => "servers/queryACL".to_string(),
        };
        self.get(&path).await
    }

    /// Get the database schema diagnostic.
    pub async fn db_schema_diagnostic(&self) -> MispResult<Value> {
        self.get("servers/schemaDiagnostics").await
    }

    // ── Events ────────────────────────────────────────────────────────

    /// List events (optionally filtered by the server-side index).
    pub async fn events(&self) -> MispResult<Vec<MispEvent>> {
        let json = self.get("events/index").await?;
        // Response is an array of objects, each may or may not be wrapped in {"Event": ...}
        let arr = json
            .as_array()
            .ok_or_else(|| MispError::UnexpectedResponse("expected array".into()))?;
        let mut events = Vec::with_capacity(arr.len());
        for item in arr {
            let event_val = if item.get("Event").is_some() {
                &item["Event"]
            } else {
                item
            };
            let event: MispEvent = serde_json::from_value(event_val.clone())?;
            events.push(event);
        }
        Ok(events)
    }

    /// Get a single event by ID.
    pub async fn get_event(&self, id: i64) -> MispResult<MispEvent> {
        let json = self.get(&format!("events/view/{id}")).await?;
        let event_val = if json.get("Event").is_some() {
            &json["Event"]
        } else {
            &json
        };
        Ok(serde_json::from_value(event_val.clone())?)
    }

    /// Check whether an event exists by ID (HEAD request).
    pub async fn event_exists(&self, id: i64) -> MispResult<bool> {
        self.head(&format!("events/view/{id}")).await
    }

    /// Create a new event.
    pub async fn add_event(&self, event: &MispEvent) -> MispResult<MispEvent> {
        let body = serde_json::json!({ "Event": serde_json::to_value(event)? });
        let json = self.post("events/add", &body).await?;
        let event_val = if json.get("Event").is_some() {
            &json["Event"]
        } else {
            &json
        };
        Ok(serde_json::from_value(event_val.clone())?)
    }

    /// Update an existing event.
    pub async fn update_event(&self, event: &MispEvent) -> MispResult<MispEvent> {
        let id = event
            .id
            .ok_or_else(|| MispError::MissingField("id".into()))?;
        let body = serde_json::json!({ "Event": serde_json::to_value(event)? });
        let json = self.post(&format!("events/edit/{id}"), &body).await?;
        let event_val = if json.get("Event").is_some() {
            &json["Event"]
        } else {
            &json
        };
        Ok(serde_json::from_value(event_val.clone())?)
    }

    /// Delete an event by ID.
    pub async fn delete_event(&self, id: i64) -> MispResult<Value> {
        self.post(&format!("events/delete/{id}"), &serde_json::json!({}))
            .await
    }

    /// Publish an event (with optional email alert).
    pub async fn publish(&self, id: i64, alert: bool) -> MispResult<Value> {
        let path = if alert {
            format!("events/alert/{id}")
        } else {
            format!("events/publish/{id}")
        };
        self.post(&path, &serde_json::json!({})).await
    }

    /// Unpublish an event.
    pub async fn unpublish(&self, id: i64) -> MispResult<Value> {
        self.post(&format!("events/unpublish/{id}"), &serde_json::json!({}))
            .await
    }

    /// Contact the reporter of an event.
    pub async fn contact_event_reporter(&self, id: i64, message: &str) -> MispResult<Value> {
        let body = serde_json::json!({ "message": message });
        self.post(&format!("events/contact/{id}"), &body).await
    }

    /// Enrich an event using expansion modules.
    pub async fn enrich_event(&self, id: i64, modules: Option<&[&str]>) -> MispResult<Value> {
        let body = match modules {
            Some(m) => serde_json::json!({ "modules": m }),
            None => serde_json::json!({}),
        };
        self.post(&format!("events/enrichEvent/{id}"), &body).await
    }

    // ── Attributes ────────────────────────────────────────────────────

    /// List attributes.
    pub async fn attributes(&self) -> MispResult<Vec<MispAttribute>> {
        let json = self.get("attributes/index").await?;
        let arr = json
            .as_array()
            .ok_or_else(|| MispError::UnexpectedResponse("expected array".into()))?;
        let mut attrs = Vec::with_capacity(arr.len());
        for item in arr {
            let attr_val = if item.get("Attribute").is_some() {
                &item["Attribute"]
            } else {
                item
            };
            let attr: MispAttribute = serde_json::from_value(attr_val.clone())?;
            attrs.push(attr);
        }
        Ok(attrs)
    }

    /// Get a single attribute by ID.
    pub async fn get_attribute(&self, id: i64) -> MispResult<MispAttribute> {
        let json = self.get(&format!("attributes/view/{id}")).await?;
        let attr_val = if json.get("Attribute").is_some() {
            &json["Attribute"]
        } else {
            &json
        };
        Ok(serde_json::from_value(attr_val.clone())?)
    }

    /// Check whether an attribute exists by ID.
    pub async fn attribute_exists(&self, id: i64) -> MispResult<bool> {
        self.head(&format!("attributes/view/{id}")).await
    }

    /// Add an attribute to an event.
    pub async fn add_attribute(
        &self,
        event_id: i64,
        attr: &MispAttribute,
    ) -> MispResult<MispAttribute> {
        let body = serde_json::to_value(attr)?;
        let json = self
            .post(&format!("attributes/add/{event_id}"), &body)
            .await?;
        let attr_val = if json.get("Attribute").is_some() {
            &json["Attribute"]
        } else {
            &json
        };
        Ok(serde_json::from_value(attr_val.clone())?)
    }

    /// Update an existing attribute.
    pub async fn update_attribute(&self, attr: &MispAttribute) -> MispResult<MispAttribute> {
        let id = attr
            .id
            .ok_or_else(|| MispError::MissingField("id".into()))?;
        let body = serde_json::to_value(attr)?;
        let json = self.post(&format!("attributes/edit/{id}"), &body).await?;
        let attr_val = if json.get("Attribute").is_some() {
            &json["Attribute"]
        } else {
            &json
        };
        Ok(serde_json::from_value(attr_val.clone())?)
    }

    /// Delete an attribute by ID. If `hard` is true, permanently remove it.
    pub async fn delete_attribute(&self, id: i64, hard: bool) -> MispResult<Value> {
        let body = if hard {
            serde_json::json!({ "hard_delete": 1 })
        } else {
            serde_json::json!({})
        };
        self.post(&format!("attributes/delete/{id}"), &body).await
    }

    /// Restore a soft-deleted attribute.
    pub async fn restore_attribute(&self, id: i64) -> MispResult<Value> {
        self.post(&format!("attributes/restore/{id}"), &serde_json::json!({}))
            .await
    }

    /// Enrich an attribute using expansion modules.
    pub async fn enrich_attribute(&self, id: i64, modules: Option<&[&str]>) -> MispResult<Value> {
        let body = match modules {
            Some(m) => serde_json::json!({ "modules": m }),
            None => serde_json::json!({}),
        };
        self.post(&format!("attributes/enrichAttribute/{id}"), &body)
            .await
    }

    // ── Tags ──────────────────────────────────────────────────────────

    /// List all tags.
    pub async fn tags(&self) -> MispResult<Vec<MispTag>> {
        let json = self.get("tags/index").await?;
        // Response may be {"Tag": [...]} or a bare array
        let arr = if let Some(tag_arr) = json.get("Tag").and_then(|v| v.as_array()) {
            tag_arr
        } else {
            json.as_array()
                .ok_or_else(|| MispError::UnexpectedResponse("expected array".into()))?
        };
        let mut tags = Vec::with_capacity(arr.len());
        for item in arr {
            let tag_val = if item.get("Tag").is_some() {
                &item["Tag"]
            } else {
                item
            };
            let tag: MispTag = serde_json::from_value(tag_val.clone())?;
            tags.push(tag);
        }
        Ok(tags)
    }

    /// Get a single tag by ID.
    pub async fn get_tag(&self, id: i64) -> MispResult<MispTag> {
        let json = self.get(&format!("tags/view/{id}")).await?;
        let tag_val = if json.get("Tag").is_some() {
            &json["Tag"]
        } else {
            &json
        };
        Ok(serde_json::from_value(tag_val.clone())?)
    }

    /// Create a new tag.
    pub async fn add_tag(&self, tag: &MispTag) -> MispResult<MispTag> {
        let body = serde_json::to_value(tag)?;
        let json = self.post("tags/add", &body).await?;
        let tag_val = if json.get("Tag").is_some() {
            &json["Tag"]
        } else {
            &json
        };
        Ok(serde_json::from_value(tag_val.clone())?)
    }

    /// Update an existing tag.
    pub async fn update_tag(&self, tag: &MispTag) -> MispResult<MispTag> {
        let id = tag.id.ok_or_else(|| MispError::MissingField("id".into()))?;
        let body = serde_json::to_value(tag)?;
        let json = self.post(&format!("tags/edit/{id}"), &body).await?;
        let tag_val = if json.get("Tag").is_some() {
            &json["Tag"]
        } else {
            &json
        };
        Ok(serde_json::from_value(tag_val.clone())?)
    }

    /// Delete a tag by ID.
    pub async fn delete_tag(&self, id: i64) -> MispResult<Value> {
        self.post(&format!("tags/delete/{id}"), &serde_json::json!({}))
            .await
    }

    /// Enable a tag.
    pub async fn enable_tag(&self, id: i64) -> MispResult<Value> {
        self.post(&format!("tags/enable/{id}"), &serde_json::json!({}))
            .await
    }

    /// Disable a tag.
    pub async fn disable_tag(&self, id: i64) -> MispResult<Value> {
        self.post(&format!("tags/disable/{id}"), &serde_json::json!({}))
            .await
    }

    /// Search tags by name.
    pub async fn search_tags(&self, name: &str, strict: bool) -> MispResult<Vec<MispTag>> {
        let path = if strict {
            format!("tags/search/{name}/1")
        } else {
            format!("tags/search/{name}")
        };
        let json = self.get(&path).await?;
        let arr = json
            .as_array()
            .ok_or_else(|| MispError::UnexpectedResponse("expected array".into()))?;
        let mut tags = Vec::with_capacity(arr.len());
        for item in arr {
            let tag_val = if item.get("Tag").is_some() {
                &item["Tag"]
            } else {
                item
            };
            let tag: MispTag = serde_json::from_value(tag_val.clone())?;
            tags.push(tag);
        }
        Ok(tags)
    }

    /// Attach a tag to an entity (event, attribute, etc.) by UUID.
    pub async fn tag(&self, uuid: &str, tag: &str, local: bool) -> MispResult<Value> {
        let body = serde_json::json!({
            "uuid": uuid,
            "tag": tag,
            "local": if local { 1 } else { 0 }
        });
        self.post("tags/attachTagToObject", &body).await
    }

    /// Remove a tag from an entity by UUID.
    pub async fn untag(&self, uuid: &str, tag: &str) -> MispResult<Value> {
        let body = serde_json::json!({
            "uuid": uuid,
            "tag": tag
        });
        self.post("tags/removeTagFromObject", &body).await
    }

    // ── Objects ──────────────────────────────────────────────────────

    /// Get a single object by ID.
    pub async fn get_object(&self, id: i64) -> MispResult<MispObject> {
        let json = self.get(&format!("objects/view/{id}")).await?;
        let obj_val = if json.get("Object").is_some() {
            &json["Object"]
        } else {
            &json
        };
        Ok(serde_json::from_value(obj_val.clone())?)
    }

    /// Check whether an object exists by ID.
    pub async fn object_exists(&self, id: i64) -> MispResult<bool> {
        self.head(&format!("objects/view/{id}")).await
    }

    /// Add an object to an event.
    pub async fn add_object(&self, event_id: i64, object: &MispObject) -> MispResult<MispObject> {
        let body = serde_json::json!({ "Object": serde_json::to_value(object)? });
        let json = self.post(&format!("objects/add/{event_id}"), &body).await?;
        let obj_val = if json.get("Object").is_some() {
            &json["Object"]
        } else {
            &json
        };
        Ok(serde_json::from_value(obj_val.clone())?)
    }

    /// Update an existing object.
    pub async fn update_object(&self, object: &MispObject) -> MispResult<MispObject> {
        let id = object
            .id
            .ok_or_else(|| MispError::MissingField("id".into()))?;
        let body = serde_json::json!({ "Object": serde_json::to_value(object)? });
        let json = self.post(&format!("objects/edit/{id}"), &body).await?;
        let obj_val = if json.get("Object").is_some() {
            &json["Object"]
        } else {
            &json
        };
        Ok(serde_json::from_value(obj_val.clone())?)
    }

    /// Delete an object by ID. If `hard` is true, permanently remove it.
    pub async fn delete_object(&self, id: i64, hard: bool) -> MispResult<Value> {
        let path = if hard {
            format!("objects/delete/{id}/1")
        } else {
            format!("objects/delete/{id}")
        };
        self.post(&path, &serde_json::json!({})).await
    }

    // ── Object References ────────────────────────────────────────────

    /// Add an object reference.
    pub async fn add_object_reference(
        &self,
        reference: &MispObjectReference,
    ) -> MispResult<MispObjectReference> {
        let body = serde_json::json!({ "ObjectReference": serde_json::to_value(reference)? });
        let json = self.post("objectReferences/add", &body).await?;
        let ref_val = if json.get("ObjectReference").is_some() {
            &json["ObjectReference"]
        } else {
            &json
        };
        Ok(serde_json::from_value(ref_val.clone())?)
    }

    /// Delete an object reference by ID.
    pub async fn delete_object_reference(&self, id: i64) -> MispResult<Value> {
        self.post(
            &format!("objectReferences/delete/{id}"),
            &serde_json::json!({}),
        )
        .await
    }

    // ── Object Templates ─────────────────────────────────────────────

    /// List all object templates.
    pub async fn object_templates(&self) -> MispResult<Vec<MispObjectTemplate>> {
        let json = self.get("objectTemplates/index").await?;
        let arr = json
            .as_array()
            .ok_or_else(|| MispError::UnexpectedResponse("expected array".into()))?;
        let mut templates = Vec::with_capacity(arr.len());
        for item in arr {
            let tmpl_val = if item.get("ObjectTemplate").is_some() {
                &item["ObjectTemplate"]
            } else {
                item
            };
            let tmpl: MispObjectTemplate = serde_json::from_value(tmpl_val.clone())?;
            templates.push(tmpl);
        }
        Ok(templates)
    }

    /// Get a single object template by ID.
    pub async fn get_object_template(&self, id: i64) -> MispResult<MispObjectTemplate> {
        let json = self.get(&format!("objectTemplates/view/{id}")).await?;
        let tmpl_val = if json.get("ObjectTemplate").is_some() {
            &json["ObjectTemplate"]
        } else {
            &json
        };
        Ok(serde_json::from_value(tmpl_val.clone())?)
    }

    /// Get a raw object template by UUID or name.
    pub async fn get_raw_object_template(&self, uuid_or_name: &str) -> MispResult<Value> {
        self.get(&format!("objectTemplates/getRaw/{uuid_or_name}"))
            .await
    }

    /// Trigger an update of all object templates.
    pub async fn update_object_templates(&self) -> MispResult<Value> {
        self.post("objectTemplates/update", &serde_json::json!({}))
            .await
    }

    // ── Attribute Proposals (Shadow Attributes) ─────────────────────

    /// List attribute proposals for an event.
    pub async fn attribute_proposals(&self, event_id: i64) -> MispResult<Vec<MispShadowAttribute>> {
        let json = self
            .get(&format!("shadowAttributes/index/{event_id}"))
            .await?;
        let arr = json
            .as_array()
            .ok_or_else(|| MispError::UnexpectedResponse("expected array".into()))?;
        let mut proposals = Vec::with_capacity(arr.len());
        for item in arr {
            let val = if item.get("ShadowAttribute").is_some() {
                &item["ShadowAttribute"]
            } else {
                item
            };
            let sa: MispShadowAttribute = serde_json::from_value(val.clone())?;
            proposals.push(sa);
        }
        Ok(proposals)
    }

    /// Get a single attribute proposal by ID.
    pub async fn get_attribute_proposal(&self, id: i64) -> MispResult<MispShadowAttribute> {
        let json = self.get(&format!("shadowAttributes/view/{id}")).await?;
        let val = if json.get("ShadowAttribute").is_some() {
            &json["ShadowAttribute"]
        } else {
            &json
        };
        Ok(serde_json::from_value(val.clone())?)
    }

    /// Propose a new attribute for an event.
    pub async fn add_attribute_proposal(
        &self,
        event_id: i64,
        attr: &MispShadowAttribute,
    ) -> MispResult<MispShadowAttribute> {
        let body = serde_json::to_value(attr)?;
        let json = self
            .post(&format!("shadowAttributes/add/{event_id}"), &body)
            .await?;
        let val = if json.get("ShadowAttribute").is_some() {
            &json["ShadowAttribute"]
        } else {
            &json
        };
        Ok(serde_json::from_value(val.clone())?)
    }

    /// Propose a modification to an existing attribute.
    pub async fn update_attribute_proposal(
        &self,
        attr_id: i64,
        attr: &MispShadowAttribute,
    ) -> MispResult<MispShadowAttribute> {
        let body = serde_json::to_value(attr)?;
        let json = self
            .post(&format!("shadowAttributes/edit/{attr_id}"), &body)
            .await?;
        let val = if json.get("ShadowAttribute").is_some() {
            &json["ShadowAttribute"]
        } else {
            &json
        };
        Ok(serde_json::from_value(val.clone())?)
    }

    /// Delete an attribute proposal.
    pub async fn delete_attribute_proposal(&self, id: i64) -> MispResult<Value> {
        self.post(
            &format!("shadowAttributes/delete/{id}"),
            &serde_json::json!({}),
        )
        .await
    }

    /// Accept an attribute proposal.
    pub async fn accept_attribute_proposal(&self, id: i64) -> MispResult<Value> {
        self.post(
            &format!("shadowAttributes/accept/{id}"),
            &serde_json::json!({}),
        )
        .await
    }

    /// Discard an attribute proposal.
    pub async fn discard_attribute_proposal(&self, id: i64) -> MispResult<Value> {
        self.post(
            &format!("shadowAttributes/discard/{id}"),
            &serde_json::json!({}),
        )
        .await
    }

    // ── Sightings ───────────────────────────────────────────────────

    /// List sightings for an attribute or event.
    pub async fn sightings(&self, id: i64) -> MispResult<Vec<MispSighting>> {
        let json = self.get(&format!("sightings/index/{id}")).await?;
        let arr = json
            .as_array()
            .ok_or_else(|| MispError::UnexpectedResponse("expected array".into()))?;
        let mut sightings = Vec::with_capacity(arr.len());
        for item in arr {
            let val = if item.get("Sighting").is_some() {
                &item["Sighting"]
            } else {
                item
            };
            let s: MispSighting = serde_json::from_value(val.clone())?;
            sightings.push(s);
        }
        Ok(sightings)
    }

    /// Add a sighting. If `attribute_id` is provided, the sighting is added
    /// to that specific attribute; otherwise it is added generically.
    pub async fn add_sighting(
        &self,
        sighting: &MispSighting,
        attribute_id: Option<i64>,
    ) -> MispResult<MispSighting> {
        let path = match attribute_id {
            Some(attr_id) => format!("sightings/add/{attr_id}"),
            None => "sightings/add".to_string(),
        };
        let body = serde_json::to_value(sighting)?;
        let json = self.post(&path, &body).await?;
        let val = if json.get("Sighting").is_some() {
            &json["Sighting"]
        } else {
            &json
        };
        Ok(serde_json::from_value(val.clone())?)
    }

    /// Delete a sighting by ID.
    pub async fn delete_sighting(&self, id: i64) -> MispResult<Value> {
        self.post(&format!("sightings/delete/{id}"), &serde_json::json!({}))
            .await
    }

    // ── Event Reports ───────────────────────────────────────────────

    /// Get a single event report by ID.
    pub async fn get_event_report(&self, id: i64) -> MispResult<MispEventReport> {
        let json = self.get(&format!("eventReports/view/{id}")).await?;
        let val = if json.get("EventReport").is_some() {
            &json["EventReport"]
        } else {
            &json
        };
        Ok(serde_json::from_value(val.clone())?)
    }

    /// Get all event reports for an event.
    pub async fn get_event_reports(&self, event_id: i64) -> MispResult<Vec<MispEventReport>> {
        let json = self
            .get(&format!("eventReports/index/event_id:{event_id}"))
            .await?;
        let arr = json
            .as_array()
            .ok_or_else(|| MispError::UnexpectedResponse("expected array".into()))?;
        let mut reports = Vec::with_capacity(arr.len());
        for item in arr {
            let val = if item.get("EventReport").is_some() {
                &item["EventReport"]
            } else {
                item
            };
            let r: MispEventReport = serde_json::from_value(val.clone())?;
            reports.push(r);
        }
        Ok(reports)
    }

    /// Add an event report to an event.
    pub async fn add_event_report(
        &self,
        event_id: i64,
        report: &MispEventReport,
    ) -> MispResult<MispEventReport> {
        let body = serde_json::to_value(report)?;
        let json = self
            .post(&format!("eventReports/add/{event_id}"), &body)
            .await?;
        let val = if json.get("EventReport").is_some() {
            &json["EventReport"]
        } else {
            &json
        };
        Ok(serde_json::from_value(val.clone())?)
    }

    /// Update an existing event report.
    pub async fn update_event_report(
        &self,
        report: &MispEventReport,
    ) -> MispResult<MispEventReport> {
        let id = report
            .id
            .ok_or_else(|| MispError::MissingField("id".into()))?;
        let body = serde_json::to_value(report)?;
        let json = self.post(&format!("eventReports/edit/{id}"), &body).await?;
        let val = if json.get("EventReport").is_some() {
            &json["EventReport"]
        } else {
            &json
        };
        Ok(serde_json::from_value(val.clone())?)
    }

    /// Delete an event report. If `hard` is true, permanently remove it.
    pub async fn delete_event_report(&self, id: i64, hard: bool) -> MispResult<Value> {
        let path = if hard {
            format!("eventReports/delete/{id}/1")
        } else {
            format!("eventReports/delete/{id}")
        };
        self.post(&path, &serde_json::json!({})).await
    }

    // ── Taxonomies ──────────────────────────────────────────────────────

    /// List all taxonomies on the MISP instance.
    pub async fn taxonomies(&self) -> MispResult<Vec<MispTaxonomy>> {
        let json = self.get("taxonomies/index").await?;
        let arr = json
            .as_array()
            .ok_or_else(|| MispError::UnexpectedResponse("expected array".into()))?;
        let mut taxonomies = Vec::with_capacity(arr.len());
        for item in arr {
            let val = if item.get("Taxonomy").is_some() {
                &item["Taxonomy"]
            } else {
                item
            };
            let t: MispTaxonomy = serde_json::from_value(val.clone())?;
            taxonomies.push(t);
        }
        Ok(taxonomies)
    }

    /// Get a single taxonomy by ID.
    pub async fn get_taxonomy(&self, id: i64) -> MispResult<MispTaxonomy> {
        let json = self.get(&format!("taxonomies/view/{id}")).await?;
        let val = if json.get("Taxonomy").is_some() {
            &json["Taxonomy"]
        } else {
            &json
        };
        Ok(serde_json::from_value(val.clone())?)
    }

    /// Enable a taxonomy on the instance.
    pub async fn enable_taxonomy(&self, id: i64) -> MispResult<Value> {
        self.post(&format!("taxonomies/enable/{id}"), &serde_json::json!({}))
            .await
    }

    /// Disable a taxonomy on the instance.
    pub async fn disable_taxonomy(&self, id: i64) -> MispResult<Value> {
        self.post(&format!("taxonomies/disable/{id}"), &serde_json::json!({}))
            .await
    }

    /// Enable all tags from a taxonomy.
    pub async fn enable_taxonomy_tags(&self, id: i64) -> MispResult<Value> {
        self.post(&format!("taxonomies/addTag/{id}"), &serde_json::json!({}))
            .await
    }

    /// Disable all tags from a taxonomy.
    pub async fn disable_taxonomy_tags(&self, id: i64) -> MispResult<Value> {
        self.post(
            &format!("taxonomies/disableTag/{id}"),
            &serde_json::json!({}),
        )
        .await
    }

    /// Update all taxonomies from the remote MISP taxonomy repository.
    pub async fn update_taxonomies(&self) -> MispResult<Value> {
        self.post("taxonomies/update", &serde_json::json!({})).await
    }

    /// Set whether a taxonomy is required before events can be published.
    pub async fn set_taxonomy_required(&self, id: i64, required: bool) -> MispResult<Value> {
        self.post(
            &format!("taxonomies/toggleRequired/{id}"),
            &serde_json::json!({ "Taxonomy": { "required": required } }),
        )
        .await
    }

    // ── Warninglists ────────────────────────────────────────────────────

    /// List all warninglists on the MISP instance.
    pub async fn warninglists(&self) -> MispResult<Vec<MispWarninglist>> {
        let json = self.get("warninglists/index").await?;
        // MISP returns {"Warninglists": [...]} wrapper
        let arr_val = if json.get("Warninglists").is_some() {
            &json["Warninglists"]
        } else {
            &json
        };
        let arr = arr_val
            .as_array()
            .ok_or_else(|| MispError::UnexpectedResponse("expected array".into()))?;
        let mut warninglists = Vec::with_capacity(arr.len());
        for item in arr {
            let val = if item.get("Warninglist").is_some() {
                &item["Warninglist"]
            } else {
                item
            };
            let w: MispWarninglist = serde_json::from_value(val.clone())?;
            warninglists.push(w);
        }
        Ok(warninglists)
    }

    /// Get a single warninglist by ID.
    pub async fn get_warninglist(&self, id: i64) -> MispResult<MispWarninglist> {
        let json = self.get(&format!("warninglists/view/{id}")).await?;
        let val = if json.get("Warninglist").is_some() {
            &json["Warninglist"]
        } else {
            &json
        };
        Ok(serde_json::from_value(val.clone())?)
    }

    /// Toggle a warninglist on/off. Provide either `id` or `name`.
    /// `force_enable` can be used to explicitly enable (`true`) or disable (`false`).
    pub async fn toggle_warninglist(
        &self,
        id: Option<i64>,
        name: Option<&str>,
        force_enable: Option<bool>,
    ) -> MispResult<Value> {
        let mut body = serde_json::Map::new();
        if let Some(id) = id {
            body.insert("id".into(), serde_json::json!(id));
        }
        if let Some(name) = name {
            body.insert("name".into(), serde_json::json!(name));
        }
        if let Some(enabled) = force_enable {
            body.insert("enabled".into(), serde_json::json!(enabled));
        }
        self.post("warninglists/toggleEnable", &Value::Object(body))
            .await
    }

    /// Enable a warninglist by ID.
    pub async fn enable_warninglist(&self, id: i64) -> MispResult<Value> {
        self.toggle_warninglist(Some(id), None, Some(true)).await
    }

    /// Disable a warninglist by ID.
    pub async fn disable_warninglist(&self, id: i64) -> MispResult<Value> {
        self.toggle_warninglist(Some(id), None, Some(false)).await
    }

    /// Check if given values are present in any enabled warninglist.
    pub async fn values_in_warninglist(&self, values: &[&str]) -> MispResult<Value> {
        self.post("warninglists/checkValue", &serde_json::json!(values))
            .await
    }

    /// Update all warninglists from the remote MISP warninglist repository.
    pub async fn update_warninglists(&self) -> MispResult<Value> {
        self.post("warninglists/update", &serde_json::json!({}))
            .await
    }

    // ── Noticelists ─────────────────────────────────────────────────────

    /// List all noticelists on the MISP instance.
    pub async fn noticelists(&self) -> MispResult<Vec<MispNoticelist>> {
        let json = self.get("noticelists/index").await?;
        let arr = json
            .as_array()
            .ok_or_else(|| MispError::UnexpectedResponse("expected array".into()))?;
        let mut noticelists = Vec::with_capacity(arr.len());
        for item in arr {
            let val = if item.get("Noticelist").is_some() {
                &item["Noticelist"]
            } else {
                item
            };
            let n: MispNoticelist = serde_json::from_value(val.clone())?;
            noticelists.push(n);
        }
        Ok(noticelists)
    }

    /// Get a single noticelist by ID.
    pub async fn get_noticelist(&self, id: i64) -> MispResult<MispNoticelist> {
        let json = self.get(&format!("noticelists/view/{id}")).await?;
        let val = if json.get("Noticelist").is_some() {
            &json["Noticelist"]
        } else {
            &json
        };
        Ok(serde_json::from_value(val.clone())?)
    }

    /// Enable a noticelist by ID.
    pub async fn enable_noticelist(&self, id: i64) -> MispResult<Value> {
        self.post(
            &format!("noticelists/toggleEnable/{id}"),
            &serde_json::json!({ "Noticelist": { "enabled": true } }),
        )
        .await
    }

    /// Disable a noticelist by ID.
    pub async fn disable_noticelist(&self, id: i64) -> MispResult<Value> {
        self.post(
            &format!("noticelists/toggleEnable/{id}"),
            &serde_json::json!({ "Noticelist": { "enabled": false } }),
        )
        .await
    }

    /// Update all noticelists from the remote MISP noticelist repository.
    pub async fn update_noticelists(&self) -> MispResult<Value> {
        self.post("noticelists/update", &serde_json::json!({}))
            .await
    }

    // ── Galaxies ────────────────────────────────────────────────────────

    /// List all galaxies on the MISP instance.
    pub async fn galaxies(&self, update: bool) -> MispResult<Vec<MispGalaxy>> {
        if update {
            self.update_galaxies().await?;
        }
        let json = self.get("galaxies/index").await?;
        let arr = json
            .as_array()
            .ok_or_else(|| MispError::UnexpectedResponse("expected array".into()))?;
        let mut galaxies = Vec::with_capacity(arr.len());
        for item in arr {
            let val = if item.get("Galaxy").is_some() {
                &item["Galaxy"]
            } else {
                item
            };
            let g: MispGalaxy = serde_json::from_value(val.clone())?;
            galaxies.push(g);
        }
        Ok(galaxies)
    }

    /// Search galaxies by value.
    pub async fn search_galaxy(&self, value: &str) -> MispResult<Value> {
        self.post("galaxies", &serde_json::json!({"value": value}))
            .await
    }

    /// Get a single galaxy by ID, optionally including its clusters.
    pub async fn get_galaxy(&self, id: i64, with_cluster: bool) -> MispResult<MispGalaxy> {
        let _ = with_cluster; // MISP always returns clusters when available
        let json = self.get(&format!("galaxies/view/{id}")).await?;
        let val = if json.get("Galaxy").is_some() {
            // Merge nested GalaxyCluster array into the Galaxy object
            let mut galaxy_val = json["Galaxy"].clone();
            if let Some(clusters) = json.get("GalaxyCluster") {
                galaxy_val["GalaxyCluster"] = clusters.clone();
            }
            galaxy_val
        } else {
            json.clone()
        };
        Ok(serde_json::from_value(val)?)
    }

    /// Search galaxy clusters using restSearch.
    pub async fn search_galaxy_clusters(
        &self,
        galaxy: &str,
        context: Option<&str>,
        searchall: bool,
    ) -> MispResult<Value> {
        let mut body = serde_json::Map::new();
        body.insert("galaxy".into(), serde_json::json!(galaxy));
        if let Some(ctx) = context {
            body.insert("context".into(), serde_json::json!(ctx));
        }
        if searchall {
            body.insert("searchall".into(), serde_json::json!(1));
        }
        self.post("galaxy_clusters/restSearch", &Value::Object(body))
            .await
    }

    /// Update all galaxies from the remote MISP galaxy repository.
    pub async fn update_galaxies(&self) -> MispResult<Value> {
        self.post("galaxies/update", &serde_json::json!({})).await
    }

    /// Get a single galaxy cluster by ID.
    pub async fn get_galaxy_cluster(&self, id: i64) -> MispResult<MispGalaxyCluster> {
        let json = self.get(&format!("galaxy_clusters/view/{id}")).await?;
        let val = if json.get("GalaxyCluster").is_some() {
            &json["GalaxyCluster"]
        } else {
            &json
        };
        Ok(serde_json::from_value(val.clone())?)
    }

    /// Add a new galaxy cluster to a galaxy.
    pub async fn add_galaxy_cluster(
        &self,
        galaxy_id: i64,
        cluster: &MispGalaxyCluster,
    ) -> MispResult<MispGalaxyCluster> {
        let body = serde_json::json!({"GalaxyCluster": cluster});
        let json = self
            .post(&format!("galaxy_clusters/add/{galaxy_id}"), &body)
            .await?;
        let val = if json.get("GalaxyCluster").is_some() {
            &json["GalaxyCluster"]
        } else {
            &json
        };
        Ok(serde_json::from_value(val.clone())?)
    }

    /// Update an existing galaxy cluster.
    pub async fn update_galaxy_cluster(
        &self,
        cluster: &MispGalaxyCluster,
    ) -> MispResult<MispGalaxyCluster> {
        let id = cluster
            .id
            .ok_or_else(|| MispError::MissingField("GalaxyCluster.id".into()))?;
        let body = serde_json::json!({"GalaxyCluster": cluster});
        let json = self
            .post(&format!("galaxy_clusters/edit/{id}"), &body)
            .await?;
        let val = if json.get("GalaxyCluster").is_some() {
            &json["GalaxyCluster"]
        } else {
            &json
        };
        Ok(serde_json::from_value(val.clone())?)
    }

    /// Publish a galaxy cluster.
    pub async fn publish_galaxy_cluster(&self, id: i64) -> MispResult<Value> {
        self.post(
            &format!("galaxy_clusters/publish/{id}"),
            &serde_json::json!({}),
        )
        .await
    }

    /// Fork a galaxy cluster into a galaxy.
    pub async fn fork_galaxy_cluster(
        &self,
        galaxy_id: i64,
        cluster: &MispGalaxyCluster,
    ) -> MispResult<Value> {
        let body = serde_json::json!({"GalaxyCluster": cluster});
        self.post(&format!("galaxy_clusters/add/{galaxy_id}"), &body)
            .await
    }

    /// Delete a galaxy cluster by ID, optionally hard-deleting.
    pub async fn delete_galaxy_cluster(&self, id: i64, hard: bool) -> MispResult<Value> {
        if hard {
            self.post(
                &format!("galaxy_clusters/delete/{id}/1"),
                &serde_json::json!({}),
            )
            .await
        } else {
            self.post(
                &format!("galaxy_clusters/delete/{id}"),
                &serde_json::json!({}),
            )
            .await
        }
    }

    /// Add a relation between galaxy clusters.
    pub async fn add_galaxy_cluster_relation(
        &self,
        relation: &MispGalaxyClusterRelation,
    ) -> MispResult<MispGalaxyClusterRelation> {
        let body = serde_json::json!({"GalaxyClusterRelation": relation});
        let json = self.post("galaxy_cluster_relations/add", &body).await?;
        let val = if json.get("GalaxyClusterRelation").is_some() {
            &json["GalaxyClusterRelation"]
        } else {
            &json
        };
        Ok(serde_json::from_value(val.clone())?)
    }

    /// Update an existing galaxy cluster relation.
    pub async fn update_galaxy_cluster_relation(
        &self,
        relation: &MispGalaxyClusterRelation,
    ) -> MispResult<MispGalaxyClusterRelation> {
        let id = relation
            .id
            .ok_or_else(|| MispError::MissingField("GalaxyClusterRelation.id".into()))?;
        let body = serde_json::json!({"GalaxyClusterRelation": relation});
        let json = self
            .post(&format!("galaxy_cluster_relations/edit/{id}"), &body)
            .await?;
        let val = if json.get("GalaxyClusterRelation").is_some() {
            &json["GalaxyClusterRelation"]
        } else {
            &json
        };
        Ok(serde_json::from_value(val.clone())?)
    }

    /// Delete a galaxy cluster relation by ID.
    pub async fn delete_galaxy_cluster_relation(&self, id: i64) -> MispResult<Value> {
        self.post(
            &format!("galaxy_cluster_relations/delete/{id}"),
            &serde_json::json!({}),
        )
        .await
    }

    /// Attach a galaxy cluster to an entity (event, attribute, etc.) by UUID.
    pub async fn attach_galaxy_cluster(
        &self,
        entity_uuid: &str,
        cluster_uuid: &str,
        local: bool,
    ) -> MispResult<Value> {
        self.post(
            &format!("galaxies/attachCluster/{entity_uuid}/{cluster_uuid}"),
            &serde_json::json!({"local": if local { 1 } else { 0 }}),
        )
        .await
    }

    // ── Decaying Models ─────────────────────────────────────────────────

    /// Update all decaying models from the MISP repository.
    pub async fn update_decaying_models(&self) -> MispResult<Value> {
        self.post("decayingModel/update", &serde_json::json!({}))
            .await
    }

    /// List all decaying models.
    pub async fn decaying_models(&self) -> MispResult<Vec<MispDecayingModel>> {
        let json = self.get("decayingModel/index").await?;
        let arr = json
            .as_array()
            .ok_or_else(|| MispError::UnexpectedResponse("expected array".into()))?;
        let mut models = Vec::with_capacity(arr.len());
        for item in arr {
            let val = if item.get("DecayingModel").is_some() {
                &item["DecayingModel"]
            } else {
                item
            };
            let m: MispDecayingModel = serde_json::from_value(val.clone())?;
            models.push(m);
        }
        Ok(models)
    }

    /// Enable a decaying model by ID.
    pub async fn enable_decaying_model(&self, id: i64) -> MispResult<Value> {
        self.post(
            &format!("decayingModel/enable/{id}"),
            &serde_json::json!({}),
        )
        .await
    }

    /// Disable a decaying model by ID.
    pub async fn disable_decaying_model(&self, id: i64) -> MispResult<Value> {
        self.post(
            &format!("decayingModel/disable/{id}"),
            &serde_json::json!({}),
        )
        .await
    }

    // ── Correlation Exclusions ──────────────────────────────────────────

    /// List all correlation exclusions.
    pub async fn correlation_exclusions(&self) -> MispResult<Vec<MispCorrelationExclusion>> {
        let json = self.get("correlationExclusions/index").await?;
        let arr = json
            .as_array()
            .ok_or_else(|| MispError::UnexpectedResponse("expected array".into()))?;
        let mut exclusions = Vec::with_capacity(arr.len());
        for item in arr {
            let val = if item.get("CorrelationExclusion").is_some() {
                &item["CorrelationExclusion"]
            } else {
                item
            };
            let e: MispCorrelationExclusion = serde_json::from_value(val.clone())?;
            exclusions.push(e);
        }
        Ok(exclusions)
    }

    /// Get a single correlation exclusion by ID.
    pub async fn get_correlation_exclusion(&self, id: i64) -> MispResult<MispCorrelationExclusion> {
        let json = self
            .get(&format!("correlationExclusions/view/{id}"))
            .await?;
        let val = if json.get("CorrelationExclusion").is_some() {
            &json["CorrelationExclusion"]
        } else {
            &json
        };
        Ok(serde_json::from_value(val.clone())?)
    }

    /// Add a new correlation exclusion.
    pub async fn add_correlation_exclusion(
        &self,
        exclusion: &MispCorrelationExclusion,
    ) -> MispResult<MispCorrelationExclusion> {
        let body = serde_json::json!({"CorrelationExclusion": exclusion});
        let json = self.post("correlationExclusions/add", &body).await?;
        let val = if json.get("CorrelationExclusion").is_some() {
            &json["CorrelationExclusion"]
        } else {
            &json
        };
        Ok(serde_json::from_value(val.clone())?)
    }

    /// Delete a correlation exclusion by ID.
    pub async fn delete_correlation_exclusion(&self, id: i64) -> MispResult<Value> {
        self.post(
            &format!("correlationExclusions/delete/{id}"),
            &serde_json::json!({}),
        )
        .await
    }

    /// Clean all correlation exclusions.
    pub async fn clean_correlation_exclusions(&self) -> MispResult<Value> {
        self.post("correlationExclusions/clean", &serde_json::json!({}))
            .await
    }
}

/// Ensure the URL has a trailing slash so `Url::join` works correctly.
fn normalize_url(url: &str) -> MispResult<Url> {
    let mut s = url.to_string();
    if !s.ends_with('/') {
        s.push('/');
    }
    Url::parse(&s).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_url_adds_trailing_slash() {
        let u = normalize_url("https://misp.example.com").unwrap();
        assert_eq!(u.as_str(), "https://misp.example.com/");
    }

    #[test]
    fn normalize_url_preserves_trailing_slash() {
        let u = normalize_url("https://misp.example.com/").unwrap();
        assert_eq!(u.as_str(), "https://misp.example.com/");
    }

    #[test]
    fn normalize_url_preserves_path() {
        let u = normalize_url("https://misp.example.com/misp").unwrap();
        assert_eq!(u.as_str(), "https://misp.example.com/misp/");
    }

    #[test]
    fn client_new_valid() {
        let client = MispClient::new("https://misp.example.com", "test-api-key", false);
        assert!(client.is_ok());
        let client = client.unwrap();
        assert_eq!(client.base_url.as_str(), "https://misp.example.com/");
        assert_eq!(client.api_key, "test-api-key");
    }

    #[test]
    fn client_new_invalid_url() {
        let client = MispClient::new("not a url :::", "key", true);
        assert!(client.is_err());
    }

    #[test]
    fn client_builder_with_options() {
        let client = MispClient::builder("https://misp.example.com", "key123")
            .ssl_verify(false)
            .timeout(Duration::from_secs(30))
            .header("X-Custom", "value")
            .build();
        assert!(client.is_ok());
    }

    #[test]
    fn describe_types_local_loads() {
        let client = MispClient::new("https://misp.example.com", "key", false).unwrap();
        let result = client.describe_types_local();
        assert!(result.is_ok());
        let json = result.unwrap();
        assert!(json["result"].is_object());
    }

    #[tokio::test]
    async fn request_preparation_sets_auth_header() {
        use wiremock::matchers::{header, method};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "my-test-key-12345", false).unwrap();

        Mock::given(method("GET"))
            .and(header("Authorization", "my-test-key-12345"))
            .and(header("Accept", "application/json"))
            .and(header("Content-Type", "application/json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true})))
            .mount(&server)
            .await;

        let result = client.get("test/endpoint").await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap()["ok"], true);
    }

    #[tokio::test]
    async fn check_response_auth_error() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "bad-key", false).unwrap();

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(403).set_body_string("Forbidden"))
            .mount(&server)
            .await;

        let result = client.get("test").await;
        assert!(matches!(result, Err(MispError::AuthError(_))));
    }

    #[tokio::test]
    async fn check_response_not_found() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(404).set_body_string("Not found"))
            .mount(&server)
            .await;

        let result = client.get("missing").await;
        assert!(matches!(result, Err(MispError::NotFound(_))));
    }

    #[tokio::test]
    async fn check_response_api_error() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(500)
                    .set_body_json(serde_json::json!({"message": "Internal error"})),
            )
            .mount(&server)
            .await;

        let result = client.get("error").await;
        match result {
            Err(MispError::ApiError { status, message }) => {
                assert_eq!(status, 500);
                assert_eq!(message, "Internal error");
            }
            other => panic!("Expected ApiError, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn head_returns_true_for_200() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let exists = client.head("events/view/1").await.unwrap();
        assert!(exists);
    }

    #[tokio::test]
    async fn head_returns_false_for_404() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let exists = client.head("events/view/999").await.unwrap();
        assert!(!exists);
    }

    #[tokio::test]
    async fn post_sends_json_body() {
        use wiremock::matchers::{body_json, method};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        let body = serde_json::json!({"value": "test-setting"});

        Mock::given(method("POST"))
            .and(body_json(&body))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"saved": true})),
            )
            .mount(&server)
            .await;

        let result = client.post("servers/serverSettingsEdit/test", &body).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn misp_instance_version_mock() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        let version_response = serde_json::json!({
            "version": "2.4.180",
            "perm_sync": false,
            "perm_sighting": false
        });

        Mock::given(method("GET"))
            .and(path("/servers/getVersion"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&version_response))
            .mount(&server)
            .await;

        let result = client.misp_instance_version().await.unwrap();
        assert_eq!(result["version"], "2.4.180");
    }

    // ── Event CRUD tests ──────────────────────────────────────────────

    #[tokio::test]
    async fn get_event_unwraps_response() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        let response = serde_json::json!({
            "Event": {
                "id": "42",
                "info": "Test Event",
                "published": false,
                "date": "2024-01-15",
                "threat_level_id": "2",
                "analysis": "1",
                "distribution": "0"
            }
        });

        Mock::given(method("GET"))
            .and(path("/events/view/42"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response))
            .mount(&server)
            .await;

        let event = client.get_event(42).await.unwrap();
        assert_eq!(event.id, Some(42));
        assert_eq!(event.info, "Test Event");
        assert!(!event.published);
        assert_eq!(event.threat_level_id, Some(2));
    }

    #[tokio::test]
    async fn add_event_sends_wrapped_body() {
        use wiremock::matchers::{body_partial_json, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("POST"))
            .and(path("/events/add"))
            .and(body_partial_json(serde_json::json!({
                "Event": { "info": "New event" }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Event": {
                    "id": "99",
                    "info": "New event",
                    "published": false,
                    "uuid": "aaaa-bbbb-cccc"
                }
            })))
            .mount(&server)
            .await;

        let mut event = crate::MispEvent::new("New event");
        let result = client.add_event(&event).await.unwrap();
        assert_eq!(result.id, Some(99));
        assert_eq!(result.info, "New event");

        // update_event requires id
        event.id = Some(99);
    }

    #[tokio::test]
    async fn event_exists_returns_true() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("HEAD"))
            .and(path("/events/view/1"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        assert!(client.event_exists(1).await.unwrap());
    }

    #[tokio::test]
    async fn delete_event_sends_post() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("POST"))
            .and(path("/events/delete/42"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"message": "Event deleted."})),
            )
            .mount(&server)
            .await;

        let result = client.delete_event(42).await.unwrap();
        assert_eq!(result["message"], "Event deleted.");
    }

    #[tokio::test]
    async fn events_list_parses_array() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        let response = serde_json::json!([
            {"id": "1", "info": "Event A", "published": true},
            {"id": "2", "info": "Event B", "published": false}
        ]);

        Mock::given(method("GET"))
            .and(path("/events/index"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response))
            .mount(&server)
            .await;

        let events = client.events().await.unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].info, "Event A");
        assert_eq!(events[1].info, "Event B");
    }

    #[tokio::test]
    async fn publish_event_with_alert() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("POST"))
            .and(path("/events/alert/5"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"saved": true, "success": true})),
            )
            .mount(&server)
            .await;

        let result = client.publish(5, true).await.unwrap();
        assert_eq!(result["saved"], true);
    }

    // ── Attribute CRUD tests ──────────────────────────────────────────

    #[tokio::test]
    async fn get_attribute_unwraps_response() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        let response = serde_json::json!({
            "Attribute": {
                "id": "7",
                "event_id": "1",
                "type": "ip-dst",
                "category": "Network activity",
                "value": "10.0.0.1",
                "to_ids": true,
                "comment": "",
                "deleted": false,
                "disable_correlation": false
            }
        });

        Mock::given(method("GET"))
            .and(path("/attributes/view/7"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response))
            .mount(&server)
            .await;

        let attr = client.get_attribute(7).await.unwrap();
        assert_eq!(attr.id, Some(7));
        assert_eq!(attr.attr_type, "ip-dst");
        assert_eq!(attr.value, "10.0.0.1");
        assert!(attr.to_ids);
    }

    #[tokio::test]
    async fn add_attribute_to_event() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("POST"))
            .and(path("/attributes/add/3"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Attribute": {
                    "id": "100",
                    "event_id": "3",
                    "type": "domain",
                    "category": "Network activity",
                    "value": "evil.com",
                    "to_ids": false,
                    "comment": "",
                    "deleted": false,
                    "disable_correlation": false
                }
            })))
            .mount(&server)
            .await;

        let attr = crate::MispAttribute::new("domain", "Network activity", "evil.com");
        let result = client.add_attribute(3, &attr).await.unwrap();
        assert_eq!(result.id, Some(100));
        assert_eq!(result.value, "evil.com");
    }

    #[tokio::test]
    async fn delete_attribute_hard() {
        use wiremock::matchers::{body_partial_json, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("POST"))
            .and(path("/attributes/delete/50"))
            .and(body_partial_json(serde_json::json!({"hard_delete": 1})))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"message": "Attribute deleted."})),
            )
            .mount(&server)
            .await;

        let result = client.delete_attribute(50, true).await.unwrap();
        assert_eq!(result["message"], "Attribute deleted.");
    }

    // ── Tag CRUD tests ────────────────────────────────────────────────

    #[tokio::test]
    async fn tags_list() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("GET"))
            .and(path("/tags/index"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"Tag": {"id": "1", "name": "tlp:white", "exportable": true, "hide_tag": false}},
                {"Tag": {"id": "2", "name": "tlp:green", "exportable": true, "hide_tag": false}}
            ])))
            .mount(&server)
            .await;

        let tags = client.tags().await.unwrap();
        assert_eq!(tags.len(), 2);
        assert_eq!(tags[0].name, "tlp:white");
        assert_eq!(tags[1].name, "tlp:green");
    }

    #[tokio::test]
    async fn add_tag_sends_body() {
        use wiremock::matchers::{body_partial_json, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("POST"))
            .and(path("/tags/add"))
            .and(body_partial_json(serde_json::json!({"name": "my-tag"})))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Tag": {"id": "55", "name": "my-tag", "colour": "#ffffff", "exportable": true, "hide_tag": false}
            })))
            .mount(&server)
            .await;

        let tag = crate::MispTag::new("my-tag");
        let result = client.add_tag(&tag).await.unwrap();
        assert_eq!(result.id, Some(55));
        assert_eq!(result.name, "my-tag");
    }

    #[tokio::test]
    async fn tag_attach_to_entity() {
        use wiremock::matchers::{body_partial_json, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("POST"))
            .and(path("/tags/attachTagToObject"))
            .and(body_partial_json(serde_json::json!({
                "uuid": "abc-123",
                "tag": "tlp:green",
                "local": 0
            })))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"saved": true, "success": "Tag attached."})),
            )
            .mount(&server)
            .await;

        let result = client.tag("abc-123", "tlp:green", false).await.unwrap();
        assert_eq!(result["saved"], true);
    }

    #[tokio::test]
    async fn search_tags_by_name() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("GET"))
            .and(path("/tags/search/tlp"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"name": "tlp:white"},
                {"name": "tlp:green"},
                {"name": "tlp:amber"}
            ])))
            .mount(&server)
            .await;

        let tags = client.search_tags("tlp", false).await.unwrap();
        assert_eq!(tags.len(), 3);
        assert_eq!(tags[0].name, "tlp:white");
    }

    // ── Object CRUD tests ────────────────────────────────────────────

    #[tokio::test]
    async fn get_object_unwraps_response() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        let response = serde_json::json!({
            "Object": {
                "id": "10",
                "name": "file",
                "meta-category": "file",
                "template_uuid": "tmpl-uuid",
                "template_version": "23",
                "distribution": "1",
                "deleted": false
            }
        });

        Mock::given(method("GET"))
            .and(path("/objects/view/10"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response))
            .mount(&server)
            .await;

        let obj = client.get_object(10).await.unwrap();
        assert_eq!(obj.id, Some(10));
        assert_eq!(obj.name, "file");
        assert_eq!(obj.template_version, Some(23));
    }

    #[tokio::test]
    async fn object_exists_returns_true() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("HEAD"))
            .and(path("/objects/view/10"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        assert!(client.object_exists(10).await.unwrap());
    }

    #[tokio::test]
    async fn add_object_to_event() {
        use wiremock::matchers::{body_partial_json, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("POST"))
            .and(path("/objects/add/5"))
            .and(body_partial_json(serde_json::json!({
                "Object": { "name": "file" }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Object": {
                    "id": "20",
                    "name": "file",
                    "event_id": "5",
                    "deleted": false
                }
            })))
            .mount(&server)
            .await;

        let obj = crate::MispObject::new("file");
        let result = client.add_object(5, &obj).await.unwrap();
        assert_eq!(result.id, Some(20));
        assert_eq!(result.name, "file");
        assert_eq!(result.event_id, Some(5));
    }

    #[tokio::test]
    async fn update_object_requires_id() {
        let client = MispClient::new("https://misp.example.com", "key", false).unwrap();
        let obj = crate::MispObject::new("file");
        let result = client.update_object(&obj).await;
        assert!(matches!(result, Err(MispError::MissingField(_))));
    }

    #[tokio::test]
    async fn delete_object_soft() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("POST"))
            .and(path("/objects/delete/10"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"message": "Object deleted."})),
            )
            .mount(&server)
            .await;

        let result = client.delete_object(10, false).await.unwrap();
        assert_eq!(result["message"], "Object deleted.");
    }

    #[tokio::test]
    async fn delete_object_hard() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("POST"))
            .and(path("/objects/delete/10/1"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"message": "Object permanently deleted."})),
            )
            .mount(&server)
            .await;

        let result = client.delete_object(10, true).await.unwrap();
        assert_eq!(result["message"], "Object permanently deleted.");
    }

    #[tokio::test]
    async fn add_object_reference_sends_wrapped() {
        use wiremock::matchers::{body_partial_json, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("POST"))
            .and(path("/objectReferences/add"))
            .and(body_partial_json(serde_json::json!({
                "ObjectReference": {
                    "referenced_uuid": "target-uuid",
                    "relationship_type": "related-to"
                }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ObjectReference": {
                    "id": "30",
                    "referenced_uuid": "target-uuid",
                    "relationship_type": "related-to",
                    "deleted": false
                }
            })))
            .mount(&server)
            .await;

        let r = crate::MispObjectReference::new("target-uuid", "related-to");
        let result = client.add_object_reference(&r).await.unwrap();
        assert_eq!(result.id, Some(30));
        assert_eq!(result.referenced_uuid.as_deref(), Some("target-uuid"));
    }

    #[tokio::test]
    async fn delete_object_reference_sends_post() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("POST"))
            .and(path("/objectReferences/delete/30"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"message": "ObjectReference deleted."})),
            )
            .mount(&server)
            .await;

        let result = client.delete_object_reference(30).await.unwrap();
        assert_eq!(result["message"], "ObjectReference deleted.");
    }

    #[tokio::test]
    async fn object_templates_list() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("GET"))
            .and(path("/objectTemplates/index"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"ObjectTemplate": {"id": "1", "name": "file", "version": "23", "active": true, "fixed": false}},
                {"ObjectTemplate": {"id": "2", "name": "domain-ip", "version": "10", "active": true, "fixed": false}}
            ])))
            .mount(&server)
            .await;

        let templates = client.object_templates().await.unwrap();
        assert_eq!(templates.len(), 2);
        assert_eq!(templates[0].name, "file");
        assert_eq!(templates[1].name, "domain-ip");
    }

    #[tokio::test]
    async fn get_object_template_by_id() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("GET"))
            .and(path("/objectTemplates/view/1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ObjectTemplate": {
                    "id": "1",
                    "uuid": "tmpl-uuid-1",
                    "name": "file",
                    "version": "23",
                    "description": "File object",
                    "meta-category": "file",
                    "active": true,
                    "fixed": false
                }
            })))
            .mount(&server)
            .await;

        let tmpl = client.get_object_template(1).await.unwrap();
        assert_eq!(tmpl.id, Some(1));
        assert_eq!(tmpl.name, "file");
        assert_eq!(tmpl.version, Some(23));
    }

    // ── Attribute Proposal (Shadow Attribute) tests ─────────────────

    #[tokio::test]
    async fn attribute_proposals_list() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("GET"))
            .and(path("/shadowAttributes/index/1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {
                    "ShadowAttribute": {
                        "id": "1",
                        "event_id": "1",
                        "old_id": "0",
                        "type": "ip-dst",
                        "category": "Network activity",
                        "value": "10.0.0.1",
                        "comment": "",
                        "to_ids": true,
                        "proposal_to_delete": false,
                        "deleted": false,
                        "disable_correlation": false
                    }
                }
            ])))
            .mount(&server)
            .await;

        let proposals = client.attribute_proposals(1).await.unwrap();
        assert_eq!(proposals.len(), 1);
        assert_eq!(proposals[0].attr_type, "ip-dst");
        assert_eq!(proposals[0].value, "10.0.0.1");
    }

    #[tokio::test]
    async fn get_attribute_proposal_unwraps() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("GET"))
            .and(path("/shadowAttributes/view/5"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ShadowAttribute": {
                    "id": "5",
                    "event_id": "1",
                    "old_id": "39",
                    "type": "md5",
                    "category": "Payload delivery",
                    "value": "abc123",
                    "comment": "Proposed fix",
                    "to_ids": true,
                    "proposal_to_delete": false,
                    "deleted": false,
                    "disable_correlation": false
                }
            })))
            .mount(&server)
            .await;

        let sa = client.get_attribute_proposal(5).await.unwrap();
        assert_eq!(sa.id, Some(5));
        assert_eq!(sa.old_id, Some(39));
        assert_eq!(sa.attr_type, "md5");
        assert_eq!(sa.comment, "Proposed fix");
    }

    #[tokio::test]
    async fn add_attribute_proposal_sends_body() {
        use wiremock::matchers::{body_partial_json, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("POST"))
            .and(path("/shadowAttributes/add/1"))
            .and(body_partial_json(serde_json::json!({
                "type": "domain",
                "category": "Network activity",
                "value": "evil.com"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ShadowAttribute": {
                    "id": "10",
                    "event_id": "1",
                    "old_id": "0",
                    "type": "domain",
                    "category": "Network activity",
                    "value": "evil.com",
                    "comment": "",
                    "to_ids": false,
                    "proposal_to_delete": false,
                    "deleted": false,
                    "disable_correlation": false
                }
            })))
            .mount(&server)
            .await;

        let sa = crate::MispShadowAttribute::new("domain", "Network activity", "evil.com");
        let result = client.add_attribute_proposal(1, &sa).await.unwrap();
        assert_eq!(result.id, Some(10));
        assert_eq!(result.value, "evil.com");
    }

    #[tokio::test]
    async fn accept_attribute_proposal_sends_post() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("POST"))
            .and(path("/shadowAttributes/accept/5"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"saved": true, "success": true})),
            )
            .mount(&server)
            .await;

        let result = client.accept_attribute_proposal(5).await.unwrap();
        assert_eq!(result["saved"], true);
    }

    #[tokio::test]
    async fn discard_attribute_proposal_sends_post() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("POST"))
            .and(path("/shadowAttributes/discard/5"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"saved": true, "success": true})),
            )
            .mount(&server)
            .await;

        let result = client.discard_attribute_proposal(5).await.unwrap();
        assert_eq!(result["saved"], true);
    }

    #[tokio::test]
    async fn delete_attribute_proposal_sends_post() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("POST"))
            .and(path("/shadowAttributes/delete/5"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"message": "Proposal deleted."})),
            )
            .mount(&server)
            .await;

        let result = client.delete_attribute_proposal(5).await.unwrap();
        assert_eq!(result["message"], "Proposal deleted.");
    }

    // ── Sighting tests ──────────────────────────────────────────────

    #[tokio::test]
    async fn sightings_list() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("GET"))
            .and(path("/sightings/index/7"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {
                    "Sighting": {
                        "id": "1",
                        "attribute_id": "7",
                        "event_id": "1",
                        "org_id": "1",
                        "date_sighting": "1700000000",
                        "type": "0",
                        "source": "honeypot"
                    }
                },
                {
                    "Sighting": {
                        "id": "2",
                        "attribute_id": "7",
                        "event_id": "1",
                        "org_id": "2",
                        "date_sighting": "1700000100",
                        "type": "1",
                        "source": "analyst"
                    }
                }
            ])))
            .mount(&server)
            .await;

        let sightings = client.sightings(7).await.unwrap();
        assert_eq!(sightings.len(), 2);
        assert_eq!(sightings[0].sighting_type, Some(0));
        assert_eq!(sightings[0].source.as_deref(), Some("honeypot"));
        assert_eq!(sightings[1].sighting_type, Some(1));
    }

    #[tokio::test]
    async fn add_sighting_to_attribute() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("POST"))
            .and(path("/sightings/add/7"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Sighting": {
                    "id": "10",
                    "attribute_id": "7",
                    "event_id": "1",
                    "type": "0",
                    "date_sighting": "1700000000"
                }
            })))
            .mount(&server)
            .await;

        let s = crate::MispSighting::new();
        let result = client.add_sighting(&s, Some(7)).await.unwrap();
        assert_eq!(result.id, Some(10));
        assert_eq!(result.attribute_id, Some(7));
    }

    #[tokio::test]
    async fn add_sighting_without_attribute_id() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("POST"))
            .and(path("/sightings/add"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Sighting": {
                    "id": "11",
                    "type": "0",
                    "date_sighting": "1700000000"
                }
            })))
            .mount(&server)
            .await;

        let s = crate::MispSighting::new();
        let result = client.add_sighting(&s, None).await.unwrap();
        assert_eq!(result.id, Some(11));
    }

    #[tokio::test]
    async fn delete_sighting_sends_post() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("POST"))
            .and(path("/sightings/delete/10"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"message": "Sighting deleted."})),
            )
            .mount(&server)
            .await;

        let result = client.delete_sighting(10).await.unwrap();
        assert_eq!(result["message"], "Sighting deleted.");
    }

    // ── Event Report tests ──────────────────────────────────────────

    #[tokio::test]
    async fn get_event_report_unwraps() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("GET"))
            .and(path("/eventReports/view/10"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "EventReport": {
                    "id": "10",
                    "uuid": "report-uuid",
                    "event_id": "1",
                    "name": "Incident Report",
                    "content": "# Analysis\n\nDetails here.",
                    "distribution": "0",
                    "deleted": false
                }
            })))
            .mount(&server)
            .await;

        let report = client.get_event_report(10).await.unwrap();
        assert_eq!(report.id, Some(10));
        assert_eq!(report.name, "Incident Report");
        assert_eq!(report.event_id, Some(1));
    }

    #[tokio::test]
    async fn get_event_reports_list() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("GET"))
            .and(path("/eventReports/index/event_id:1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {
                    "EventReport": {
                        "id": "10",
                        "event_id": "1",
                        "name": "Report A",
                        "content": "Content A",
                        "deleted": false
                    }
                },
                {
                    "EventReport": {
                        "id": "11",
                        "event_id": "1",
                        "name": "Report B",
                        "content": "Content B",
                        "deleted": false
                    }
                }
            ])))
            .mount(&server)
            .await;

        let reports = client.get_event_reports(1).await.unwrap();
        assert_eq!(reports.len(), 2);
        assert_eq!(reports[0].name, "Report A");
        assert_eq!(reports[1].name, "Report B");
    }

    #[tokio::test]
    async fn add_event_report_sends_body() {
        use wiremock::matchers::{body_partial_json, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("POST"))
            .and(path("/eventReports/add/1"))
            .and(body_partial_json(serde_json::json!({
                "name": "New Report",
                "content": "Report content"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "EventReport": {
                    "id": "20",
                    "event_id": "1",
                    "name": "New Report",
                    "content": "Report content",
                    "deleted": false
                }
            })))
            .mount(&server)
            .await;

        let report = crate::MispEventReport::new("New Report", "Report content");
        let result = client.add_event_report(1, &report).await.unwrap();
        assert_eq!(result.id, Some(20));
        assert_eq!(result.name, "New Report");
    }

    #[tokio::test]
    async fn update_event_report_requires_id() {
        let client = MispClient::new("https://misp.example.com", "key", false).unwrap();
        let report = crate::MispEventReport::new("Test", "Content");
        let result = client.update_event_report(&report).await;
        assert!(matches!(result, Err(MispError::MissingField(_))));
    }

    #[tokio::test]
    async fn delete_event_report_soft() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("POST"))
            .and(path("/eventReports/delete/10"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"message": "Event report deleted."})),
            )
            .mount(&server)
            .await;

        let result = client.delete_event_report(10, false).await.unwrap();
        assert_eq!(result["message"], "Event report deleted.");
    }

    #[tokio::test]
    async fn delete_event_report_hard() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("POST"))
            .and(path("/eventReports/delete/10/1"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(
                    serde_json::json!({"message": "Event report permanently deleted."}),
                ),
            )
            .mount(&server)
            .await;

        let result = client.delete_event_report(10, true).await.unwrap();
        assert_eq!(result["message"], "Event report permanently deleted.");
    }

    // ── Taxonomy tests ──────────────────────────────────────────────────

    #[tokio::test]
    async fn taxonomies_list() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("GET"))
            .and(path("/taxonomies/index"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {
                    "Taxonomy": {
                        "id": "1",
                        "namespace": "tlp",
                        "description": "Traffic Light Protocol",
                        "version": "5",
                        "enabled": true,
                        "exclusive": true,
                        "required": false,
                        "highlighted": false
                    }
                },
                {
                    "Taxonomy": {
                        "id": "2",
                        "namespace": "admiralty-scale",
                        "description": "Admiralty Scale",
                        "version": "3",
                        "enabled": false,
                        "exclusive": false,
                        "required": false,
                        "highlighted": false
                    }
                }
            ])))
            .mount(&server)
            .await;

        let taxonomies = client.taxonomies().await.unwrap();
        assert_eq!(taxonomies.len(), 2);
        assert_eq!(taxonomies[0].namespace, "tlp");
        assert!(taxonomies[0].enabled);
        assert_eq!(taxonomies[1].namespace, "admiralty-scale");
        assert!(!taxonomies[1].enabled);
    }

    #[tokio::test]
    async fn get_taxonomy_unwraps() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("GET"))
            .and(path("/taxonomies/view/1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Taxonomy": {
                    "id": "1",
                    "namespace": "tlp",
                    "description": "Traffic Light Protocol",
                    "version": "5",
                    "enabled": true,
                    "exclusive": true,
                    "required": false,
                    "highlighted": false
                }
            })))
            .mount(&server)
            .await;

        let t = client.get_taxonomy(1).await.unwrap();
        assert_eq!(t.id, Some(1));
        assert_eq!(t.namespace, "tlp");
        assert!(t.enabled);
    }

    #[tokio::test]
    async fn enable_taxonomy_posts() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("POST"))
            .and(path("/taxonomies/enable/1"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"message": "Taxonomy enabled."})),
            )
            .mount(&server)
            .await;

        let result = client.enable_taxonomy(1).await.unwrap();
        assert_eq!(result["message"], "Taxonomy enabled.");
    }

    #[tokio::test]
    async fn disable_taxonomy_posts() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("POST"))
            .and(path("/taxonomies/disable/1"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"message": "Taxonomy disabled."})),
            )
            .mount(&server)
            .await;

        let result = client.disable_taxonomy(1).await.unwrap();
        assert_eq!(result["message"], "Taxonomy disabled.");
    }

    #[tokio::test]
    async fn enable_taxonomy_tags_posts() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("POST"))
            .and(path("/taxonomies/addTag/1"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"message": "Tags added."})),
            )
            .mount(&server)
            .await;

        let result = client.enable_taxonomy_tags(1).await.unwrap();
        assert_eq!(result["message"], "Tags added.");
    }

    #[tokio::test]
    async fn update_taxonomies_posts() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("POST"))
            .and(path("/taxonomies/update"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"message": "Taxonomies updated."})),
            )
            .mount(&server)
            .await;

        let result = client.update_taxonomies().await.unwrap();
        assert_eq!(result["message"], "Taxonomies updated.");
    }

    #[tokio::test]
    async fn set_taxonomy_required_posts() {
        use wiremock::matchers::{body_partial_json, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("POST"))
            .and(path("/taxonomies/toggleRequired/1"))
            .and(body_partial_json(
                serde_json::json!({"Taxonomy": {"required": true}}),
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"message": "Taxonomy set as required."})),
            )
            .mount(&server)
            .await;

        let result = client.set_taxonomy_required(1, true).await.unwrap();
        assert_eq!(result["message"], "Taxonomy set as required.");
    }

    // ── Warninglist tests ───────────────────────────────────────────────

    #[tokio::test]
    async fn warninglists_list() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("GET"))
            .and(path("/warninglists/index"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Warninglists": [
                    {
                        "Warninglist": {
                            "id": "10",
                            "name": "Public DNS resolvers",
                            "type": "string",
                            "description": "Known DNS resolvers",
                            "version": "3",
                            "enabled": true,
                            "warninglist_entry_count": "42"
                        }
                    },
                    {
                        "Warninglist": {
                            "id": "11",
                            "name": "RFC 5735 CIDR blocks",
                            "type": "cidr",
                            "description": "RFC 5735 address blocks",
                            "version": "2",
                            "enabled": false,
                            "warninglist_entry_count": "15"
                        }
                    }
                ]
            })))
            .mount(&server)
            .await;

        let warninglists = client.warninglists().await.unwrap();
        assert_eq!(warninglists.len(), 2);
        assert_eq!(warninglists[0].name, "Public DNS resolvers");
        assert!(warninglists[0].enabled);
        assert_eq!(warninglists[1].name, "RFC 5735 CIDR blocks");
        assert!(!warninglists[1].enabled);
    }

    #[tokio::test]
    async fn get_warninglist_unwraps() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("GET"))
            .and(path("/warninglists/view/10"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Warninglist": {
                    "id": "10",
                    "name": "Public DNS resolvers",
                    "type": "string",
                    "version": "3",
                    "enabled": true,
                    "warninglist_entry_count": "42"
                }
            })))
            .mount(&server)
            .await;

        let w = client.get_warninglist(10).await.unwrap();
        assert_eq!(w.id, Some(10));
        assert_eq!(w.name, "Public DNS resolvers");
        assert!(w.enabled);
    }

    #[tokio::test]
    async fn enable_warninglist_sends_toggle() {
        use wiremock::matchers::{body_partial_json, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("POST"))
            .and(path("/warninglists/toggleEnable"))
            .and(body_partial_json(
                serde_json::json!({"id": 10, "enabled": true}),
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"message": "Warninglist enabled."})),
            )
            .mount(&server)
            .await;

        let result = client.enable_warninglist(10).await.unwrap();
        assert_eq!(result["message"], "Warninglist enabled.");
    }

    #[tokio::test]
    async fn disable_warninglist_sends_toggle() {
        use wiremock::matchers::{body_partial_json, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("POST"))
            .and(path("/warninglists/toggleEnable"))
            .and(body_partial_json(
                serde_json::json!({"id": 5, "enabled": false}),
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"message": "Warninglist disabled."})),
            )
            .mount(&server)
            .await;

        let result = client.disable_warninglist(5).await.unwrap();
        assert_eq!(result["message"], "Warninglist disabled.");
    }

    #[tokio::test]
    async fn values_in_warninglist_posts_values() {
        use wiremock::matchers::{body_json, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("POST"))
            .and(path("/warninglists/checkValue"))
            .and(body_json(serde_json::json!(["8.8.8.8", "1.1.1.1"])))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "8.8.8.8": [{"id": 10, "name": "Public DNS resolvers"}],
                "1.1.1.1": [{"id": 10, "name": "Public DNS resolvers"}]
            })))
            .mount(&server)
            .await;

        let result = client
            .values_in_warninglist(&["8.8.8.8", "1.1.1.1"])
            .await
            .unwrap();
        assert!(result["8.8.8.8"].is_array());
        assert!(result["1.1.1.1"].is_array());
    }

    #[tokio::test]
    async fn update_warninglists_posts() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("POST"))
            .and(path("/warninglists/update"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"message": "Warninglists updated."})),
            )
            .mount(&server)
            .await;

        let result = client.update_warninglists().await.unwrap();
        assert_eq!(result["message"], "Warninglists updated.");
    }

    // ── Noticelist tests ────────────────────────────────────────────────

    #[tokio::test]
    async fn noticelists_list() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("GET"))
            .and(path("/noticelists/index"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {
                    "Noticelist": {
                        "id": "5",
                        "name": "rfc1918",
                        "expanded_name": "RFC 1918 — Private IP ranges",
                        "version": "2",
                        "enabled": true
                    }
                },
                {
                    "Noticelist": {
                        "id": "6",
                        "name": "rfc5735",
                        "expanded_name": "RFC 5735 — Special Use IPv4 Addresses",
                        "version": "1",
                        "enabled": false
                    }
                }
            ])))
            .mount(&server)
            .await;

        let noticelists = client.noticelists().await.unwrap();
        assert_eq!(noticelists.len(), 2);
        assert_eq!(noticelists[0].name, "rfc1918");
        assert!(noticelists[0].enabled);
        assert_eq!(noticelists[1].name, "rfc5735");
        assert!(!noticelists[1].enabled);
    }

    #[tokio::test]
    async fn get_noticelist_unwraps() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("GET"))
            .and(path("/noticelists/view/5"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Noticelist": {
                    "id": "5",
                    "name": "rfc1918",
                    "expanded_name": "RFC 1918 — Private IP ranges",
                    "version": "2",
                    "enabled": true
                }
            })))
            .mount(&server)
            .await;

        let n = client.get_noticelist(5).await.unwrap();
        assert_eq!(n.id, Some(5));
        assert_eq!(n.name, "rfc1918");
        assert!(n.enabled);
    }

    #[tokio::test]
    async fn enable_noticelist_posts() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("POST"))
            .and(path("/noticelists/toggleEnable/5"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"message": "Noticelist enabled."})),
            )
            .mount(&server)
            .await;

        let result = client.enable_noticelist(5).await.unwrap();
        assert_eq!(result["message"], "Noticelist enabled.");
    }

    #[tokio::test]
    async fn disable_noticelist_posts() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("POST"))
            .and(path("/noticelists/toggleEnable/5"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"message": "Noticelist disabled."})),
            )
            .mount(&server)
            .await;

        let result = client.disable_noticelist(5).await.unwrap();
        assert_eq!(result["message"], "Noticelist disabled.");
    }

    #[tokio::test]
    async fn update_noticelists_posts() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("POST"))
            .and(path("/noticelists/update"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"message": "Noticelists updated."})),
            )
            .mount(&server)
            .await;

        let result = client.update_noticelists().await.unwrap();
        assert_eq!(result["message"], "Noticelists updated.");
    }

    // ── Galaxy tests ────────────────────────────────────────────────────

    #[tokio::test]
    async fn galaxies_list() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("GET"))
            .and(path("/galaxies/index"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {
                    "Galaxy": {
                        "id": "1",
                        "uuid": "galaxy-uuid-1",
                        "name": "Threat Actor",
                        "type": "threat-actor",
                        "description": "Known threat actors",
                        "version": "5",
                        "namespace": "misp",
                        "enabled": true,
                        "local_only": false
                    }
                },
                {
                    "Galaxy": {
                        "id": "2",
                        "uuid": "galaxy-uuid-2",
                        "name": "Tool",
                        "type": "tool",
                        "description": "Known tools",
                        "version": "3",
                        "namespace": "misp",
                        "enabled": true,
                        "local_only": false
                    }
                }
            ])))
            .mount(&server)
            .await;

        let galaxies = client.galaxies(false).await.unwrap();
        assert_eq!(galaxies.len(), 2);
        assert_eq!(galaxies[0].name, "Threat Actor");
        assert_eq!(galaxies[0].galaxy_type.as_deref(), Some("threat-actor"));
        assert_eq!(galaxies[1].name, "Tool");
    }

    #[tokio::test]
    async fn get_galaxy_with_clusters() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("GET"))
            .and(path("/galaxies/view/1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Galaxy": {
                    "id": "1",
                    "name": "Threat Actor",
                    "type": "threat-actor",
                    "enabled": true,
                    "local_only": false
                },
                "GalaxyCluster": [
                    {
                        "id": "42",
                        "value": "APT28",
                        "type": "threat-actor",
                        "default": true,
                        "published": true
                    }
                ]
            })))
            .mount(&server)
            .await;

        let g = client.get_galaxy(1, true).await.unwrap();
        assert_eq!(g.id, Some(1));
        assert_eq!(g.name, "Threat Actor");
        assert_eq!(g.galaxy_clusters.len(), 1);
        assert_eq!(g.galaxy_clusters[0].value, "APT28");
    }

    #[tokio::test]
    async fn search_galaxy_posts() {
        use wiremock::matchers::{body_partial_json, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("POST"))
            .and(path("/galaxies"))
            .and(body_partial_json(serde_json::json!({"value": "APT"})))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!([{"Galaxy": {"id": "1", "name": "Threat Actor"}}]),
            ))
            .mount(&server)
            .await;

        let result = client.search_galaxy("APT").await.unwrap();
        assert!(result.is_array());
    }

    #[tokio::test]
    async fn update_galaxies_posts() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("POST"))
            .and(path("/galaxies/update"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"message": "Galaxies updated."})),
            )
            .mount(&server)
            .await;

        let result = client.update_galaxies().await.unwrap();
        assert_eq!(result["message"], "Galaxies updated.");
    }

    #[tokio::test]
    async fn get_galaxy_cluster_unwraps() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("GET"))
            .and(path("/galaxy_clusters/view/42"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "GalaxyCluster": {
                    "id": "42",
                    "uuid": "cluster-uuid",
                    "type": "threat-actor",
                    "value": "APT28",
                    "description": "Russian threat actor",
                    "default": true,
                    "published": true
                }
            })))
            .mount(&server)
            .await;

        let c = client.get_galaxy_cluster(42).await.unwrap();
        assert_eq!(c.id, Some(42));
        assert_eq!(c.value, "APT28");
        assert!(c.default);
    }

    #[tokio::test]
    async fn add_galaxy_cluster_sends_body() {
        use wiremock::matchers::{body_partial_json, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("POST"))
            .and(path("/galaxy_clusters/add/1"))
            .and(body_partial_json(
                serde_json::json!({"GalaxyCluster": {"value": "NewCluster"}}),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "GalaxyCluster": {
                    "id": "100",
                    "value": "NewCluster",
                    "default": false,
                    "published": false
                }
            })))
            .mount(&server)
            .await;

        let c = crate::MispGalaxyCluster::new("NewCluster");
        let result = client.add_galaxy_cluster(1, &c).await.unwrap();
        assert_eq!(result.id, Some(100));
        assert_eq!(result.value, "NewCluster");
    }

    #[tokio::test]
    async fn update_galaxy_cluster_requires_id() {
        let client = MispClient::new("https://misp.example.com", "key", false).unwrap();
        let c = crate::MispGalaxyCluster::new("test");
        let result = client.update_galaxy_cluster(&c).await;
        assert!(matches!(result, Err(MispError::MissingField(_))));
    }

    #[tokio::test]
    async fn publish_galaxy_cluster_posts() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("POST"))
            .and(path("/galaxy_clusters/publish/42"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"saved": true, "success": true})),
            )
            .mount(&server)
            .await;

        let result = client.publish_galaxy_cluster(42).await.unwrap();
        assert_eq!(result["saved"], true);
    }

    #[tokio::test]
    async fn delete_galaxy_cluster_soft() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("POST"))
            .and(path("/galaxy_clusters/delete/42"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"message": "Cluster deleted."})),
            )
            .mount(&server)
            .await;

        let result = client.delete_galaxy_cluster(42, false).await.unwrap();
        assert_eq!(result["message"], "Cluster deleted.");
    }

    #[tokio::test]
    async fn delete_galaxy_cluster_hard() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("POST"))
            .and(path("/galaxy_clusters/delete/42/1"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"message": "Cluster permanently deleted."})),
            )
            .mount(&server)
            .await;

        let result = client.delete_galaxy_cluster(42, true).await.unwrap();
        assert_eq!(result["message"], "Cluster permanently deleted.");
    }

    #[tokio::test]
    async fn add_galaxy_cluster_relation_sends_body() {
        use wiremock::matchers::{body_partial_json, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("POST"))
            .and(path("/galaxy_cluster_relations/add"))
            .and(body_partial_json(serde_json::json!({
                "GalaxyClusterRelation": {
                    "referenced_galaxy_cluster_uuid": "target-uuid",
                    "relationship_type": "uses"
                }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "GalaxyClusterRelation": {
                    "id": "10",
                    "galaxy_cluster_id": "42",
                    "referenced_galaxy_cluster_uuid": "target-uuid",
                    "relationship_type": "uses"
                }
            })))
            .mount(&server)
            .await;

        let r = crate::MispGalaxyClusterRelation::new("target-uuid", "uses");
        let result = client.add_galaxy_cluster_relation(&r).await.unwrap();
        assert_eq!(result.id, Some(10));
        assert_eq!(result.relationship_type.as_deref(), Some("uses"));
    }

    #[tokio::test]
    async fn delete_galaxy_cluster_relation_posts() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("POST"))
            .and(path("/galaxy_cluster_relations/delete/10"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"message": "Relation deleted."})),
            )
            .mount(&server)
            .await;

        let result = client.delete_galaxy_cluster_relation(10).await.unwrap();
        assert_eq!(result["message"], "Relation deleted.");
    }

    #[tokio::test]
    async fn attach_galaxy_cluster_posts() {
        use wiremock::matchers::{body_partial_json, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("POST"))
            .and(path("/galaxies/attachCluster/event-uuid/cluster-uuid"))
            .and(body_partial_json(serde_json::json!({"local": 1})))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(
                    serde_json::json!({"saved": true, "success": "Cluster attached."}),
                ),
            )
            .mount(&server)
            .await;

        let result = client
            .attach_galaxy_cluster("event-uuid", "cluster-uuid", true)
            .await
            .unwrap();
        assert_eq!(result["saved"], true);
    }

    // ── Decaying Model tests ────────────────────────────────────────────

    #[tokio::test]
    async fn decaying_models_list() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("GET"))
            .and(path("/decayingModel/index"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {
                    "DecayingModel": {
                        "id": "1",
                        "name": "NIDS Simple Decaying Model",
                        "description": "Simple model",
                        "enabled": true,
                        "all_orgs": true
                    }
                },
                {
                    "DecayingModel": {
                        "id": "2",
                        "name": "Phishing Decaying Model",
                        "description": "Phishing model",
                        "enabled": false,
                        "all_orgs": false
                    }
                }
            ])))
            .mount(&server)
            .await;

        let models = client.decaying_models().await.unwrap();
        assert_eq!(models.len(), 2);
        assert_eq!(models[0].name, "NIDS Simple Decaying Model");
        assert!(models[0].enabled);
        assert_eq!(models[1].name, "Phishing Decaying Model");
        assert!(!models[1].enabled);
    }

    #[tokio::test]
    async fn enable_decaying_model_posts() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("POST"))
            .and(path("/decayingModel/enable/1"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"message": "Model enabled."})),
            )
            .mount(&server)
            .await;

        let result = client.enable_decaying_model(1).await.unwrap();
        assert_eq!(result["message"], "Model enabled.");
    }

    #[tokio::test]
    async fn disable_decaying_model_posts() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("POST"))
            .and(path("/decayingModel/disable/1"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"message": "Model disabled."})),
            )
            .mount(&server)
            .await;

        let result = client.disable_decaying_model(1).await.unwrap();
        assert_eq!(result["message"], "Model disabled.");
    }

    #[tokio::test]
    async fn update_decaying_models_posts() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("POST"))
            .and(path("/decayingModel/update"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"message": "Models updated."})),
            )
            .mount(&server)
            .await;

        let result = client.update_decaying_models().await.unwrap();
        assert_eq!(result["message"], "Models updated.");
    }

    // ── Correlation Exclusion tests ─────────────────────────────────────

    #[tokio::test]
    async fn correlation_exclusions_list() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("GET"))
            .and(path("/correlationExclusions/index"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {
                    "CorrelationExclusion": {
                        "id": "1",
                        "value": "8.8.8.8",
                        "comment": "Google DNS"
                    }
                },
                {
                    "CorrelationExclusion": {
                        "id": "2",
                        "value": "1.1.1.1",
                        "comment": "Cloudflare DNS"
                    }
                }
            ])))
            .mount(&server)
            .await;

        let exclusions = client.correlation_exclusions().await.unwrap();
        assert_eq!(exclusions.len(), 2);
        assert_eq!(exclusions[0].value, "8.8.8.8");
        assert_eq!(exclusions[0].comment.as_deref(), Some("Google DNS"));
        assert_eq!(exclusions[1].value, "1.1.1.1");
    }

    #[tokio::test]
    async fn get_correlation_exclusion_unwraps() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("GET"))
            .and(path("/correlationExclusions/view/1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "CorrelationExclusion": {
                    "id": "1",
                    "value": "8.8.8.8",
                    "comment": "Google DNS"
                }
            })))
            .mount(&server)
            .await;

        let e = client.get_correlation_exclusion(1).await.unwrap();
        assert_eq!(e.id, Some(1));
        assert_eq!(e.value, "8.8.8.8");
    }

    #[tokio::test]
    async fn add_correlation_exclusion_sends_body() {
        use wiremock::matchers::{body_partial_json, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("POST"))
            .and(path("/correlationExclusions/add"))
            .and(body_partial_json(
                serde_json::json!({"CorrelationExclusion": {"value": "8.8.8.8"}}),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "CorrelationExclusion": {
                    "id": "10",
                    "value": "8.8.8.8",
                    "comment": null
                }
            })))
            .mount(&server)
            .await;

        let e = crate::MispCorrelationExclusion::new("8.8.8.8");
        let result = client.add_correlation_exclusion(&e).await.unwrap();
        assert_eq!(result.id, Some(10));
        assert_eq!(result.value, "8.8.8.8");
    }

    #[tokio::test]
    async fn delete_correlation_exclusion_posts() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("POST"))
            .and(path("/correlationExclusions/delete/1"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"message": "Exclusion deleted."})),
            )
            .mount(&server)
            .await;

        let result = client.delete_correlation_exclusion(1).await.unwrap();
        assert_eq!(result["message"], "Exclusion deleted.");
    }

    #[tokio::test]
    async fn clean_correlation_exclusions_posts() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("POST"))
            .and(path("/correlationExclusions/clean"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"message": "Exclusions cleaned."})),
            )
            .mount(&server)
            .await;

        let result = client.clean_correlation_exclusions().await.unwrap();
        assert_eq!(result["message"], "Exclusions cleaned.");
    }
}
