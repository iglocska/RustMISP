use std::collections::HashMap;
use std::time::Duration;

use reqwest::header::{ACCEPT, CONTENT_TYPE, HeaderMap, HeaderValue};
use reqwest::{Client, Method, Response, StatusCode};
use serde_json::Value;
use url::Url;

use crate::error::{MispError, MispResult};
use crate::models::attribute::MispAttribute;
use crate::models::event::MispEvent;
use crate::models::tag::MispTag;

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
}
