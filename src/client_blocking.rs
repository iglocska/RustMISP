//! Blocking (synchronous) wrapper around [`MispClient`].
//!
//! This module provides [`MispClientBlocking`], which wraps the async
//! [`MispClient`] with a dedicated Tokio runtime so that every method
//! can be called from synchronous code.
//!
//! Enable via the `blocking` Cargo feature:
//!
//! ```toml
//! [dependencies]
//! rustmisp = { version = "0.1", features = ["blocking"] }
//! ```

use std::time::Duration;

use serde_json::Value;
use url::Url;

use crate::client::{MispClient, MispClientBuilder};
use crate::error::{MispError, MispResult};
use crate::models::attribute::MispAttribute;
use crate::models::blocklist::{MispEventBlocklist, MispOrganisationBlocklist};
use crate::models::community::MispCommunity;
use crate::models::correlation::{MispCorrelationExclusion, MispDecayingModel};
use crate::models::event::MispEvent;
use crate::models::event_delegation::MispEventDelegation;
use crate::models::event_report::MispEventReport;
use crate::models::feed::MispFeed;
use crate::models::galaxy::{MispGalaxy, MispGalaxyCluster, MispGalaxyClusterRelation};
use crate::models::noticelist::MispNoticelist;
use crate::models::object::{MispObject, MispObjectReference, MispObjectTemplate};
use crate::models::organisation::MispOrganisation;
use crate::models::server::MispServer;
use crate::models::shadow_attribute::MispShadowAttribute;
use crate::models::sharing_group::MispSharingGroup;
use crate::models::sighting::MispSighting;
use crate::models::tag::MispTag;
use crate::models::taxonomy::MispTaxonomy;
use crate::models::user::{MispInbox, MispRole, MispUser};
use crate::models::user_setting::MispUserSetting;
use crate::models::warninglist::MispWarninglist;
use crate::search::{SearchController, SearchParameters};

/// Builder for constructing a [`MispClientBlocking`] with advanced options.
///
/// Mirrors [`MispClientBuilder`] but produces a blocking client.
#[derive(Debug)]
pub struct MispClientBlockingBuilder {
    inner: MispClientBuilder,
}

impl MispClientBlockingBuilder {
    /// Disable TLS certificate verification.
    pub fn ssl_verify(mut self, verify: bool) -> Self {
        self.inner = self.inner.ssl_verify(verify);
        self
    }

    /// Set a request timeout.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.inner = self.inner.timeout(timeout);
        self
    }

    /// Set an HTTP proxy URL.
    pub fn proxy(mut self, proxy: impl Into<String>) -> Self {
        self.inner = self.inner.proxy(proxy);
        self
    }

    /// Add a custom header to all requests.
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.inner = self.inner.header(name, value);
        self
    }

    /// Build the [`MispClientBlocking`].
    pub fn build(self) -> MispResult<MispClientBlocking> {
        let client = self.inner.build()?;
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| MispError::InvalidInput(format!("Failed to create runtime: {e}")))?;
        Ok(MispClientBlocking { inner: client, rt })
    }
}

/// Synchronous MISP client that wraps the async [`MispClient`].
///
/// Each method blocks the calling thread until the operation completes.
/// Internally uses a dedicated single-threaded Tokio runtime.
///
/// # Example
/// ```no_run
/// use rustmisp::MispClientBlocking;
///
/// let client = MispClientBlocking::new(
///     "https://misp.example.com",
///     "your-api-key",
///     false,
/// ).unwrap();
///
/// let version = client.misp_instance_version().unwrap();
/// println!("{}", version);
/// ```
pub struct MispClientBlocking {
    inner: MispClient,
    rt: tokio::runtime::Runtime,
}

// Manual Debug impl because tokio::runtime::Runtime does not implement Debug
impl std::fmt::Debug for MispClientBlocking {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MispClientBlocking")
            .field("inner", &self.inner)
            .finish_non_exhaustive()
    }
}

impl MispClientBlocking {
    /// Create a new blocking MISP client.
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
    pub fn builder(url: impl Into<String>, key: impl Into<String>) -> MispClientBlockingBuilder {
        MispClientBlockingBuilder {
            inner: MispClient::builder(url, key),
        }
    }

    /// Get the base URL of this client.
    pub fn base_url(&self) -> &Url {
        self.inner.base_url()
    }

    /// Get a reference to the underlying async client.
    pub fn inner(&self) -> &MispClient {
        &self.inner
    }

    // ── Server / Instance Info ────────────────────────────────────────

    /// Load `describeTypes` from the bundled JSON file.
    pub fn describe_types_local(&self) -> MispResult<Value> {
        self.inner.describe_types_local()
    }

    /// Load `describeTypes` from the remote MISP instance.
    pub fn describe_types_remote(&self) -> MispResult<Value> {
        self.rt.block_on(self.inner.describe_types_remote())
    }

    /// Get the MISP instance version.
    pub fn misp_instance_version(&self) -> MispResult<Value> {
        self.rt.block_on(self.inner.misp_instance_version())
    }

    /// Get the library version as reported by the MISP instance.
    pub fn version(&self) -> MispResult<Value> {
        self.rt.block_on(self.inner.version())
    }

    /// Get the MISP server settings.
    pub fn server_settings(&self) -> MispResult<Value> {
        self.rt.block_on(self.inner.server_settings())
    }

    /// Get a specific server setting.
    pub fn get_server_setting(&self, setting: &str) -> MispResult<Value> {
        self.rt.block_on(self.inner.get_server_setting(setting))
    }

    /// Set a server setting.
    pub fn set_server_setting(&self, setting: &str, value: impl Into<Value>) -> MispResult<Value> {
        self.rt
            .block_on(self.inner.set_server_setting(setting, value))
    }

    /// Query the ACL system for debugging.
    pub fn remote_acl(&self, debug_type: Option<&str>) -> MispResult<Value> {
        self.rt.block_on(self.inner.remote_acl(debug_type))
    }

    /// Get database schema diagnostics.
    pub fn db_schema_diagnostic(&self) -> MispResult<Value> {
        self.rt.block_on(self.inner.db_schema_diagnostic())
    }

    // ── Events ────────────────────────────────────────────────────────

    /// List all events.
    pub fn events(&self) -> MispResult<Vec<MispEvent>> {
        self.rt.block_on(self.inner.events())
    }

    /// Get a single event by ID.
    pub fn get_event(&self, id: i64) -> MispResult<MispEvent> {
        self.rt.block_on(self.inner.get_event(id))
    }

    /// Check if an event exists by ID.
    pub fn event_exists(&self, id: i64) -> MispResult<bool> {
        self.rt.block_on(self.inner.event_exists(id))
    }

    /// Create a new event.
    pub fn add_event(&self, event: &MispEvent) -> MispResult<MispEvent> {
        self.rt.block_on(self.inner.add_event(event))
    }

    /// Update an existing event.
    pub fn update_event(&self, event: &MispEvent) -> MispResult<MispEvent> {
        self.rt.block_on(self.inner.update_event(event))
    }

    /// Delete an event by ID.
    pub fn delete_event(&self, id: i64) -> MispResult<Value> {
        self.rt.block_on(self.inner.delete_event(id))
    }

    /// Publish an event. If `alert` is true, sends email alerts.
    pub fn publish(&self, id: i64, alert: bool) -> MispResult<Value> {
        self.rt.block_on(self.inner.publish(id, alert))
    }

    /// Unpublish an event.
    pub fn unpublish(&self, id: i64) -> MispResult<Value> {
        self.rt.block_on(self.inner.unpublish(id))
    }

    /// Contact the reporter of an event.
    pub fn contact_event_reporter(&self, id: i64, message: &str) -> MispResult<Value> {
        self.rt
            .block_on(self.inner.contact_event_reporter(id, message))
    }

    /// Enrich an event using enrichment modules.
    pub fn enrich_event(&self, id: i64, modules: Option<&[&str]>) -> MispResult<Value> {
        self.rt.block_on(self.inner.enrich_event(id, modules))
    }

    // ── Attributes ────────────────────────────────────────────────────

    /// List all attributes.
    pub fn attributes(&self) -> MispResult<Vec<MispAttribute>> {
        self.rt.block_on(self.inner.attributes())
    }

    /// Get a single attribute by ID.
    pub fn get_attribute(&self, id: i64) -> MispResult<MispAttribute> {
        self.rt.block_on(self.inner.get_attribute(id))
    }

    /// Check if an attribute exists by ID.
    pub fn attribute_exists(&self, id: i64) -> MispResult<bool> {
        self.rt.block_on(self.inner.attribute_exists(id))
    }

    /// Add an attribute to an event.
    pub fn add_attribute(&self, event_id: i64, attr: &MispAttribute) -> MispResult<MispAttribute> {
        self.rt.block_on(self.inner.add_attribute(event_id, attr))
    }

    /// Update an existing attribute.
    pub fn update_attribute(&self, attr: &MispAttribute) -> MispResult<MispAttribute> {
        self.rt.block_on(self.inner.update_attribute(attr))
    }

    /// Delete an attribute by ID. If `hard` is true, permanently remove it.
    pub fn delete_attribute(&self, id: i64, hard: bool) -> MispResult<Value> {
        self.rt.block_on(self.inner.delete_attribute(id, hard))
    }

    /// Restore a soft-deleted attribute.
    pub fn restore_attribute(&self, id: i64) -> MispResult<Value> {
        self.rt.block_on(self.inner.restore_attribute(id))
    }

    /// Enrich an attribute using enrichment modules.
    pub fn enrich_attribute(&self, id: i64, modules: Option<&[&str]>) -> MispResult<Value> {
        self.rt.block_on(self.inner.enrich_attribute(id, modules))
    }

    // ── Tags ──────────────────────────────────────────────────────────

    /// List all tags.
    pub fn tags(&self) -> MispResult<Vec<MispTag>> {
        self.rt.block_on(self.inner.tags())
    }

    /// Get a single tag by ID.
    pub fn get_tag(&self, id: i64) -> MispResult<MispTag> {
        self.rt.block_on(self.inner.get_tag(id))
    }

    /// Create a new tag.
    pub fn add_tag(&self, tag: &MispTag) -> MispResult<MispTag> {
        self.rt.block_on(self.inner.add_tag(tag))
    }

    /// Update an existing tag.
    pub fn update_tag(&self, tag: &MispTag) -> MispResult<MispTag> {
        self.rt.block_on(self.inner.update_tag(tag))
    }

    /// Delete a tag by ID.
    pub fn delete_tag(&self, id: i64) -> MispResult<Value> {
        self.rt.block_on(self.inner.delete_tag(id))
    }

    /// Enable a tag by ID.
    pub fn enable_tag(&self, id: i64) -> MispResult<Value> {
        self.rt.block_on(self.inner.enable_tag(id))
    }

    /// Disable a tag by ID.
    pub fn disable_tag(&self, id: i64) -> MispResult<Value> {
        self.rt.block_on(self.inner.disable_tag(id))
    }

    /// Search for tags by name.
    pub fn search_tags(&self, name: &str, strict: bool) -> MispResult<Vec<MispTag>> {
        self.rt.block_on(self.inner.search_tags(name, strict))
    }

    /// Attach a tag to an entity (event, attribute, etc.) by UUID.
    pub fn tag(&self, uuid: &str, tag: &str, local: bool) -> MispResult<Value> {
        self.rt.block_on(self.inner.tag(uuid, tag, local))
    }

    /// Remove a tag from an entity by UUID.
    pub fn untag(&self, uuid: &str, tag: &str) -> MispResult<Value> {
        self.rt.block_on(self.inner.untag(uuid, tag))
    }

    // ── Objects ───────────────────────────────────────────────────────

    /// Get a single object by ID.
    pub fn get_object(&self, id: i64) -> MispResult<MispObject> {
        self.rt.block_on(self.inner.get_object(id))
    }

    /// Check if an object exists by ID.
    pub fn object_exists(&self, id: i64) -> MispResult<bool> {
        self.rt.block_on(self.inner.object_exists(id))
    }

    /// Add an object to an event.
    pub fn add_object(&self, event_id: i64, object: &MispObject) -> MispResult<MispObject> {
        self.rt.block_on(self.inner.add_object(event_id, object))
    }

    /// Update an existing object.
    pub fn update_object(&self, object: &MispObject) -> MispResult<MispObject> {
        self.rt.block_on(self.inner.update_object(object))
    }

    /// Delete an object by ID. If `hard` is true, permanently remove it.
    pub fn delete_object(&self, id: i64, hard: bool) -> MispResult<Value> {
        self.rt.block_on(self.inner.delete_object(id, hard))
    }

    /// Add a reference between objects.
    pub fn add_object_reference(
        &self,
        reference: &MispObjectReference,
    ) -> MispResult<MispObjectReference> {
        self.rt.block_on(self.inner.add_object_reference(reference))
    }

    /// Delete an object reference by ID.
    pub fn delete_object_reference(&self, id: i64) -> MispResult<Value> {
        self.rt.block_on(self.inner.delete_object_reference(id))
    }

    /// List all object templates.
    pub fn object_templates(&self) -> MispResult<Vec<MispObjectTemplate>> {
        self.rt.block_on(self.inner.object_templates())
    }

    /// Get a single object template by ID.
    pub fn get_object_template(&self, id: i64) -> MispResult<MispObjectTemplate> {
        self.rt.block_on(self.inner.get_object_template(id))
    }

    /// Get a raw object template by UUID or name.
    pub fn get_raw_object_template(&self, uuid_or_name: &str) -> MispResult<Value> {
        self.rt
            .block_on(self.inner.get_raw_object_template(uuid_or_name))
    }

    /// Update all object templates from the MISP repository.
    pub fn update_object_templates(&self) -> MispResult<Value> {
        self.rt.block_on(self.inner.update_object_templates())
    }

    // ── Shadow Attributes / Proposals ─────────────────────────────────

    /// List attribute proposals for an event.
    pub fn attribute_proposals(&self, event_id: i64) -> MispResult<Vec<MispShadowAttribute>> {
        self.rt.block_on(self.inner.attribute_proposals(event_id))
    }

    /// Get a single attribute proposal by ID.
    pub fn get_attribute_proposal(&self, id: i64) -> MispResult<MispShadowAttribute> {
        self.rt.block_on(self.inner.get_attribute_proposal(id))
    }

    /// Propose a new attribute for an event.
    pub fn add_attribute_proposal(
        &self,
        event_id: i64,
        attr: &MispShadowAttribute,
    ) -> MispResult<MispShadowAttribute> {
        self.rt
            .block_on(self.inner.add_attribute_proposal(event_id, attr))
    }

    /// Propose a modification to an existing attribute.
    pub fn update_attribute_proposal(
        &self,
        attr_id: i64,
        attr: &MispShadowAttribute,
    ) -> MispResult<MispShadowAttribute> {
        self.rt
            .block_on(self.inner.update_attribute_proposal(attr_id, attr))
    }

    /// Delete an attribute proposal.
    pub fn delete_attribute_proposal(&self, id: i64) -> MispResult<Value> {
        self.rt.block_on(self.inner.delete_attribute_proposal(id))
    }

    /// Accept an attribute proposal.
    pub fn accept_attribute_proposal(&self, id: i64) -> MispResult<Value> {
        self.rt.block_on(self.inner.accept_attribute_proposal(id))
    }

    /// Discard an attribute proposal.
    pub fn discard_attribute_proposal(&self, id: i64) -> MispResult<Value> {
        self.rt.block_on(self.inner.discard_attribute_proposal(id))
    }

    // ── Sightings ─────────────────────────────────────────────────────

    /// List sightings for an entity by ID.
    pub fn sightings(&self, id: i64) -> MispResult<Vec<MispSighting>> {
        self.rt.block_on(self.inner.sightings(id))
    }

    /// Add a sighting, optionally scoped to an attribute.
    pub fn add_sighting(
        &self,
        sighting: &MispSighting,
        attribute_id: Option<i64>,
    ) -> MispResult<MispSighting> {
        self.rt
            .block_on(self.inner.add_sighting(sighting, attribute_id))
    }

    /// Delete a sighting by ID.
    pub fn delete_sighting(&self, id: i64) -> MispResult<Value> {
        self.rt.block_on(self.inner.delete_sighting(id))
    }

    // ── Event Reports ─────────────────────────────────────────────────

    /// Get a single event report by ID.
    pub fn get_event_report(&self, id: i64) -> MispResult<MispEventReport> {
        self.rt.block_on(self.inner.get_event_report(id))
    }

    /// Get all event reports for an event.
    pub fn get_event_reports(&self, event_id: i64) -> MispResult<Vec<MispEventReport>> {
        self.rt.block_on(self.inner.get_event_reports(event_id))
    }

    /// Add an event report to an event.
    pub fn add_event_report(
        &self,
        event_id: i64,
        report: &MispEventReport,
    ) -> MispResult<MispEventReport> {
        self.rt
            .block_on(self.inner.add_event_report(event_id, report))
    }

    /// Update an existing event report.
    pub fn update_event_report(&self, report: &MispEventReport) -> MispResult<MispEventReport> {
        self.rt.block_on(self.inner.update_event_report(report))
    }

    /// Delete an event report. If `hard` is true, permanently remove it.
    pub fn delete_event_report(&self, id: i64, hard: bool) -> MispResult<Value> {
        self.rt.block_on(self.inner.delete_event_report(id, hard))
    }

    // ── Taxonomies ────────────────────────────────────────────────────

    /// List all taxonomies.
    pub fn taxonomies(&self) -> MispResult<Vec<MispTaxonomy>> {
        self.rt.block_on(self.inner.taxonomies())
    }

    /// Get a single taxonomy by ID.
    pub fn get_taxonomy(&self, id: i64) -> MispResult<MispTaxonomy> {
        self.rt.block_on(self.inner.get_taxonomy(id))
    }

    /// Enable a taxonomy by ID.
    pub fn enable_taxonomy(&self, id: i64) -> MispResult<Value> {
        self.rt.block_on(self.inner.enable_taxonomy(id))
    }

    /// Disable a taxonomy by ID.
    pub fn disable_taxonomy(&self, id: i64) -> MispResult<Value> {
        self.rt.block_on(self.inner.disable_taxonomy(id))
    }

    /// Enable tags for a taxonomy.
    pub fn enable_taxonomy_tags(&self, id: i64) -> MispResult<Value> {
        self.rt.block_on(self.inner.enable_taxonomy_tags(id))
    }

    /// Disable tags for a taxonomy.
    pub fn disable_taxonomy_tags(&self, id: i64) -> MispResult<Value> {
        self.rt.block_on(self.inner.disable_taxonomy_tags(id))
    }

    /// Update all taxonomies from the remote MISP taxonomy repository.
    pub fn update_taxonomies(&self) -> MispResult<Value> {
        self.rt.block_on(self.inner.update_taxonomies())
    }

    /// Set whether a taxonomy is required.
    pub fn set_taxonomy_required(&self, id: i64, required: bool) -> MispResult<Value> {
        self.rt
            .block_on(self.inner.set_taxonomy_required(id, required))
    }

    // ── Warninglists ──────────────────────────────────────────────────

    /// List all warninglists.
    pub fn warninglists(&self) -> MispResult<Vec<MispWarninglist>> {
        self.rt.block_on(self.inner.warninglists())
    }

    /// Get a single warninglist by ID.
    pub fn get_warninglist(&self, id: i64) -> MispResult<MispWarninglist> {
        self.rt.block_on(self.inner.get_warninglist(id))
    }

    /// Toggle a warninglist's enabled state.
    pub fn toggle_warninglist(
        &self,
        id: Option<i64>,
        name: Option<&str>,
        force_enable: Option<bool>,
    ) -> MispResult<Value> {
        self.rt
            .block_on(self.inner.toggle_warninglist(id, name, force_enable))
    }

    /// Enable a warninglist by ID.
    pub fn enable_warninglist(&self, id: i64) -> MispResult<Value> {
        self.rt.block_on(self.inner.enable_warninglist(id))
    }

    /// Disable a warninglist by ID.
    pub fn disable_warninglist(&self, id: i64) -> MispResult<Value> {
        self.rt.block_on(self.inner.disable_warninglist(id))
    }

    /// Check if given values are present in any enabled warninglist.
    pub fn values_in_warninglist(&self, values: &[&str]) -> MispResult<Value> {
        self.rt.block_on(self.inner.values_in_warninglist(values))
    }

    /// Update all warninglists from the remote MISP warninglist repository.
    pub fn update_warninglists(&self) -> MispResult<Value> {
        self.rt.block_on(self.inner.update_warninglists())
    }

    // ── Noticelists ───────────────────────────────────────────────────

    /// List all noticelists.
    pub fn noticelists(&self) -> MispResult<Vec<MispNoticelist>> {
        self.rt.block_on(self.inner.noticelists())
    }

    /// Get a single noticelist by ID.
    pub fn get_noticelist(&self, id: i64) -> MispResult<MispNoticelist> {
        self.rt.block_on(self.inner.get_noticelist(id))
    }

    /// Enable a noticelist by ID.
    pub fn enable_noticelist(&self, id: i64) -> MispResult<Value> {
        self.rt.block_on(self.inner.enable_noticelist(id))
    }

    /// Disable a noticelist by ID.
    pub fn disable_noticelist(&self, id: i64) -> MispResult<Value> {
        self.rt.block_on(self.inner.disable_noticelist(id))
    }

    /// Update all noticelists from the remote MISP noticelist repository.
    pub fn update_noticelists(&self) -> MispResult<Value> {
        self.rt.block_on(self.inner.update_noticelists())
    }

    // ── Galaxies ──────────────────────────────────────────────────────

    /// List all galaxies. If `update` is true, update from remote first.
    pub fn galaxies(&self, update: bool) -> MispResult<Vec<MispGalaxy>> {
        self.rt.block_on(self.inner.galaxies(update))
    }

    /// Search galaxies by value.
    pub fn search_galaxy(&self, value: &str) -> MispResult<Value> {
        self.rt.block_on(self.inner.search_galaxy(value))
    }

    /// Get a single galaxy by ID. If `with_cluster` is true, include clusters.
    pub fn get_galaxy(&self, id: i64, with_cluster: bool) -> MispResult<MispGalaxy> {
        self.rt.block_on(self.inner.get_galaxy(id, with_cluster))
    }

    /// Search galaxy clusters.
    pub fn search_galaxy_clusters(
        &self,
        galaxy: &str,
        context: Option<&str>,
        searchall: bool,
    ) -> MispResult<Value> {
        self.rt.block_on(
            self.inner
                .search_galaxy_clusters(galaxy, context, searchall),
        )
    }

    /// Update all galaxies from the remote MISP galaxy repository.
    pub fn update_galaxies(&self) -> MispResult<Value> {
        self.rt.block_on(self.inner.update_galaxies())
    }

    /// Get a single galaxy cluster by ID.
    pub fn get_galaxy_cluster(&self, id: i64) -> MispResult<MispGalaxyCluster> {
        self.rt.block_on(self.inner.get_galaxy_cluster(id))
    }

    /// Add a new galaxy cluster to a galaxy.
    pub fn add_galaxy_cluster(
        &self,
        galaxy_id: i64,
        cluster: &MispGalaxyCluster,
    ) -> MispResult<MispGalaxyCluster> {
        self.rt
            .block_on(self.inner.add_galaxy_cluster(galaxy_id, cluster))
    }

    /// Update an existing galaxy cluster.
    pub fn update_galaxy_cluster(
        &self,
        cluster: &MispGalaxyCluster,
    ) -> MispResult<MispGalaxyCluster> {
        self.rt.block_on(self.inner.update_galaxy_cluster(cluster))
    }

    /// Publish a galaxy cluster.
    pub fn publish_galaxy_cluster(&self, id: i64) -> MispResult<Value> {
        self.rt.block_on(self.inner.publish_galaxy_cluster(id))
    }

    /// Fork a galaxy cluster into a galaxy.
    pub fn fork_galaxy_cluster(
        &self,
        galaxy_id: i64,
        cluster: &MispGalaxyCluster,
    ) -> MispResult<Value> {
        self.rt
            .block_on(self.inner.fork_galaxy_cluster(galaxy_id, cluster))
    }

    /// Delete a galaxy cluster by ID, optionally hard-deleting.
    pub fn delete_galaxy_cluster(&self, id: i64, hard: bool) -> MispResult<Value> {
        self.rt.block_on(self.inner.delete_galaxy_cluster(id, hard))
    }

    /// Add a relation between galaxy clusters.
    pub fn add_galaxy_cluster_relation(
        &self,
        relation: &MispGalaxyClusterRelation,
    ) -> MispResult<MispGalaxyClusterRelation> {
        self.rt
            .block_on(self.inner.add_galaxy_cluster_relation(relation))
    }

    /// Update a galaxy cluster relation.
    pub fn update_galaxy_cluster_relation(
        &self,
        relation: &MispGalaxyClusterRelation,
    ) -> MispResult<MispGalaxyClusterRelation> {
        self.rt
            .block_on(self.inner.update_galaxy_cluster_relation(relation))
    }

    /// Delete a galaxy cluster relation by ID.
    pub fn delete_galaxy_cluster_relation(&self, id: i64) -> MispResult<Value> {
        self.rt
            .block_on(self.inner.delete_galaxy_cluster_relation(id))
    }

    /// Attach a galaxy cluster to an entity.
    pub fn attach_galaxy_cluster(
        &self,
        entity_uuid: &str,
        cluster_uuid: &str,
        local: bool,
    ) -> MispResult<Value> {
        self.rt.block_on(
            self.inner
                .attach_galaxy_cluster(entity_uuid, cluster_uuid, local),
        )
    }

    // ── Decaying Models ───────────────────────────────────────────────

    /// Update all decaying models from the MISP repository.
    pub fn update_decaying_models(&self) -> MispResult<Value> {
        self.rt.block_on(self.inner.update_decaying_models())
    }

    /// List all decaying models.
    pub fn decaying_models(&self) -> MispResult<Vec<MispDecayingModel>> {
        self.rt.block_on(self.inner.decaying_models())
    }

    /// Enable a decaying model by ID.
    pub fn enable_decaying_model(&self, id: i64) -> MispResult<Value> {
        self.rt.block_on(self.inner.enable_decaying_model(id))
    }

    /// Disable a decaying model by ID.
    pub fn disable_decaying_model(&self, id: i64) -> MispResult<Value> {
        self.rt.block_on(self.inner.disable_decaying_model(id))
    }

    // ── Correlation Exclusions ────────────────────────────────────────

    /// List all correlation exclusions.
    pub fn correlation_exclusions(&self) -> MispResult<Vec<MispCorrelationExclusion>> {
        self.rt.block_on(self.inner.correlation_exclusions())
    }

    /// Get a single correlation exclusion by ID.
    pub fn get_correlation_exclusion(&self, id: i64) -> MispResult<MispCorrelationExclusion> {
        self.rt.block_on(self.inner.get_correlation_exclusion(id))
    }

    /// Add a new correlation exclusion.
    pub fn add_correlation_exclusion(
        &self,
        exclusion: &MispCorrelationExclusion,
    ) -> MispResult<MispCorrelationExclusion> {
        self.rt
            .block_on(self.inner.add_correlation_exclusion(exclusion))
    }

    /// Delete a correlation exclusion by ID.
    pub fn delete_correlation_exclusion(&self, id: i64) -> MispResult<Value> {
        self.rt
            .block_on(self.inner.delete_correlation_exclusion(id))
    }

    /// Clean all correlation exclusions.
    pub fn clean_correlation_exclusions(&self) -> MispResult<Value> {
        self.rt.block_on(self.inner.clean_correlation_exclusions())
    }

    // ── Organisations ─────────────────────────────────────────────────

    /// List organisations.
    pub fn organisations(
        &self,
        scope: Option<&str>,
        search: Option<&str>,
    ) -> MispResult<Vec<MispOrganisation>> {
        self.rt.block_on(self.inner.organisations(scope, search))
    }

    /// Get a single organisation by ID.
    pub fn get_organisation(&self, id: i64) -> MispResult<MispOrganisation> {
        self.rt.block_on(self.inner.get_organisation(id))
    }

    /// Check if an organisation exists by ID.
    pub fn organisation_exists(&self, id: i64) -> MispResult<bool> {
        self.rt.block_on(self.inner.organisation_exists(id))
    }

    /// Create a new organisation (requires admin).
    pub fn add_organisation(&self, org: &MispOrganisation) -> MispResult<MispOrganisation> {
        self.rt.block_on(self.inner.add_organisation(org))
    }

    /// Update an existing organisation (requires admin).
    pub fn update_organisation(&self, org: &MispOrganisation) -> MispResult<MispOrganisation> {
        self.rt.block_on(self.inner.update_organisation(org))
    }

    /// Delete an organisation by ID (requires admin).
    pub fn delete_organisation(&self, id: i64) -> MispResult<Value> {
        self.rt.block_on(self.inner.delete_organisation(id))
    }

    // ── Users ─────────────────────────────────────────────────────────

    /// List users (requires admin).
    pub fn users(
        &self,
        search: Option<&str>,
        organisation: Option<i64>,
    ) -> MispResult<Vec<MispUser>> {
        self.rt.block_on(self.inner.users(search, organisation))
    }

    /// Get a single user by ID.
    pub fn get_user(&self, id: i64) -> MispResult<MispUser> {
        self.rt.block_on(self.inner.get_user(id))
    }

    /// Reset and return a new API auth key for a user.
    pub fn get_new_authkey(&self, user_id: i64) -> MispResult<String> {
        self.rt.block_on(self.inner.get_new_authkey(user_id))
    }

    /// Create a new user (requires admin).
    pub fn add_user(&self, user: &MispUser) -> MispResult<MispUser> {
        self.rt.block_on(self.inner.add_user(user))
    }

    /// Update an existing user (requires admin).
    pub fn update_user(&self, user: &MispUser) -> MispResult<MispUser> {
        self.rt.block_on(self.inner.update_user(user))
    }

    /// Delete a user by ID (requires admin).
    pub fn delete_user(&self, id: i64) -> MispResult<Value> {
        self.rt.block_on(self.inner.delete_user(id))
    }

    /// Change the password of the currently authenticated user.
    pub fn change_user_password(&self, password: &str) -> MispResult<Value> {
        self.rt.block_on(self.inner.change_user_password(password))
    }

    /// List pending user registrations.
    pub fn user_registrations(&self) -> MispResult<Vec<MispInbox>> {
        self.rt.block_on(self.inner.user_registrations())
    }

    /// Accept a user registration request.
    #[allow(clippy::too_many_arguments)]
    pub fn accept_user_registration(
        &self,
        id: i64,
        org_id: Option<i64>,
        role_id: Option<i64>,
        perm_sync: Option<bool>,
        perm_publish: Option<bool>,
        perm_admin: Option<bool>,
    ) -> MispResult<Value> {
        self.rt.block_on(self.inner.accept_user_registration(
            id,
            org_id,
            role_id,
            perm_sync,
            perm_publish,
            perm_admin,
        ))
    }

    /// Discard (decline) a user registration request.
    pub fn discard_user_registration(&self, id: i64) -> MispResult<Value> {
        self.rt.block_on(self.inner.discard_user_registration(id))
    }

    /// Get a heartbeat from the user endpoint.
    pub fn users_heartbeat(&self) -> MispResult<Value> {
        self.rt.block_on(self.inner.users_heartbeat())
    }

    /// List all roles.
    pub fn roles(&self) -> MispResult<Vec<MispRole>> {
        self.rt.block_on(self.inner.roles())
    }

    /// Create a new role (requires admin).
    pub fn add_role(&self, role: &MispRole) -> MispResult<MispRole> {
        self.rt.block_on(self.inner.add_role(role))
    }

    /// Update an existing role (requires admin).
    pub fn update_role(&self, role: &MispRole) -> MispResult<MispRole> {
        self.rt.block_on(self.inner.update_role(role))
    }

    /// Set a role as the default role.
    pub fn set_default_role(&self, id: i64) -> MispResult<Value> {
        self.rt.block_on(self.inner.set_default_role(id))
    }

    /// Delete a role by ID (requires admin).
    pub fn delete_role(&self, id: i64) -> MispResult<Value> {
        self.rt.block_on(self.inner.delete_role(id))
    }

    // ── Servers ───────────────────────────────────────────────────────

    /// List all servers.
    pub fn servers(&self) -> MispResult<Vec<MispServer>> {
        self.rt.block_on(self.inner.servers())
    }

    /// Get the sync configuration for importing into another instance.
    pub fn get_sync_config(&self) -> MispResult<Value> {
        self.rt.block_on(self.inner.get_sync_config())
    }

    /// Import a server configuration.
    pub fn import_server(&self, server: &Value) -> MispResult<Value> {
        self.rt.block_on(self.inner.import_server(server))
    }

    /// Add a new server.
    pub fn add_server(&self, server: &MispServer) -> MispResult<MispServer> {
        self.rt.block_on(self.inner.add_server(server))
    }

    /// Update an existing server.
    pub fn update_server(&self, server: &MispServer) -> MispResult<MispServer> {
        self.rt.block_on(self.inner.update_server(server))
    }

    /// Delete a server by ID.
    pub fn delete_server(&self, id: i64) -> MispResult<Value> {
        self.rt.block_on(self.inner.delete_server(id))
    }

    /// Pull data from a remote server.
    pub fn server_pull(&self, id: i64, event_id: Option<i64>) -> MispResult<Value> {
        self.rt.block_on(self.inner.server_pull(id, event_id))
    }

    /// Push data to a remote server.
    pub fn server_push(&self, id: i64, event_id: Option<i64>) -> MispResult<Value> {
        self.rt.block_on(self.inner.server_push(id, event_id))
    }

    /// Test a server connection.
    pub fn test_server(&self, id: i64) -> MispResult<Value> {
        self.rt.block_on(self.inner.test_server(id))
    }

    /// Update the MISP instance.
    pub fn update_misp(&self) -> MispResult<Value> {
        self.rt.block_on(self.inner.update_misp())
    }

    /// Restart all workers.
    pub fn restart_workers(&self) -> MispResult<Value> {
        self.rt.block_on(self.inner.restart_workers())
    }

    /// Restart dead workers.
    pub fn restart_dead_workers(&self) -> MispResult<Value> {
        self.rt.block_on(self.inner.restart_dead_workers())
    }

    /// Get the status of all workers.
    pub fn get_workers(&self) -> MispResult<Value> {
        self.rt.block_on(self.inner.get_workers())
    }

    /// Start a specific worker type.
    pub fn start_worker(&self, worker_type: &str) -> MispResult<Value> {
        self.rt.block_on(self.inner.start_worker(worker_type))
    }

    /// Stop a worker by PID.
    pub fn stop_worker_by_pid(&self, pid: i64) -> MispResult<Value> {
        self.rt.block_on(self.inner.stop_worker_by_pid(pid))
    }

    /// Kill all workers.
    pub fn kill_all_workers(&self) -> MispResult<Value> {
        self.rt.block_on(self.inner.kill_all_workers())
    }

    // ── Feeds ─────────────────────────────────────────────────────────

    /// List all feeds.
    pub fn feeds(&self) -> MispResult<Vec<MispFeed>> {
        self.rt.block_on(self.inner.feeds())
    }

    /// Get a single feed by ID.
    pub fn get_feed(&self, id: i64) -> MispResult<MispFeed> {
        self.rt.block_on(self.inner.get_feed(id))
    }

    /// Add a new feed.
    pub fn add_feed(&self, feed: &MispFeed) -> MispResult<MispFeed> {
        self.rt.block_on(self.inner.add_feed(feed))
    }

    /// Update an existing feed.
    pub fn update_feed(&self, feed: &MispFeed) -> MispResult<MispFeed> {
        self.rt.block_on(self.inner.update_feed(feed))
    }

    /// Delete a feed by ID.
    pub fn delete_feed(&self, id: i64) -> MispResult<Value> {
        self.rt.block_on(self.inner.delete_feed(id))
    }

    /// Enable a feed by ID.
    pub fn enable_feed(&self, id: i64) -> MispResult<Value> {
        self.rt.block_on(self.inner.enable_feed(id))
    }

    /// Disable a feed by ID.
    pub fn disable_feed(&self, id: i64) -> MispResult<Value> {
        self.rt.block_on(self.inner.disable_feed(id))
    }

    /// Enable caching for a feed by ID.
    pub fn enable_feed_cache(&self, id: i64) -> MispResult<Value> {
        self.rt.block_on(self.inner.enable_feed_cache(id))
    }

    /// Disable caching for a feed by ID.
    pub fn disable_feed_cache(&self, id: i64) -> MispResult<Value> {
        self.rt.block_on(self.inner.disable_feed_cache(id))
    }

    /// Fetch data from a specific feed.
    pub fn fetch_feed(&self, id: i64) -> MispResult<Value> {
        self.rt.block_on(self.inner.fetch_feed(id))
    }

    /// Cache all feeds.
    pub fn cache_all_feeds(&self) -> MispResult<Value> {
        self.rt.block_on(self.inner.cache_all_feeds())
    }

    /// Cache a specific feed.
    pub fn cache_feed(&self, id: i64) -> MispResult<Value> {
        self.rt.block_on(self.inner.cache_feed(id))
    }

    /// Cache all freetext feeds.
    pub fn cache_freetext_feeds(&self) -> MispResult<Value> {
        self.rt.block_on(self.inner.cache_freetext_feeds())
    }

    /// Cache all MISP feeds.
    pub fn cache_misp_feeds(&self) -> MispResult<Value> {
        self.rt.block_on(self.inner.cache_misp_feeds())
    }

    /// Compare feeds.
    pub fn compare_feeds(&self) -> MispResult<Value> {
        self.rt.block_on(self.inner.compare_feeds())
    }

    /// Load the default set of feeds.
    pub fn load_default_feeds(&self) -> MispResult<Value> {
        self.rt.block_on(self.inner.load_default_feeds())
    }

    // ── Sharing Groups ────────────────────────────────────────────────

    /// List all sharing groups.
    pub fn sharing_groups(&self) -> MispResult<Vec<MispSharingGroup>> {
        self.rt.block_on(self.inner.sharing_groups())
    }

    /// Get a single sharing group by ID.
    pub fn get_sharing_group(&self, id: i64) -> MispResult<MispSharingGroup> {
        self.rt.block_on(self.inner.get_sharing_group(id))
    }

    /// Add a new sharing group.
    pub fn add_sharing_group(&self, sg: &MispSharingGroup) -> MispResult<MispSharingGroup> {
        self.rt.block_on(self.inner.add_sharing_group(sg))
    }

    /// Update an existing sharing group.
    pub fn update_sharing_group(&self, sg: &MispSharingGroup) -> MispResult<MispSharingGroup> {
        self.rt.block_on(self.inner.update_sharing_group(sg))
    }

    /// Check if a sharing group exists by ID.
    pub fn sharing_group_exists(&self, id: i64) -> MispResult<bool> {
        self.rt.block_on(self.inner.sharing_group_exists(id))
    }

    /// Delete a sharing group by ID.
    pub fn delete_sharing_group(&self, id: i64) -> MispResult<Value> {
        self.rt.block_on(self.inner.delete_sharing_group(id))
    }

    /// Add an organisation to a sharing group.
    pub fn add_org_to_sharing_group(&self, sg_id: i64, org_id: i64) -> MispResult<Value> {
        self.rt
            .block_on(self.inner.add_org_to_sharing_group(sg_id, org_id))
    }

    /// Remove an organisation from a sharing group.
    pub fn remove_org_from_sharing_group(&self, sg_id: i64, org_id: i64) -> MispResult<Value> {
        self.rt
            .block_on(self.inner.remove_org_from_sharing_group(sg_id, org_id))
    }

    /// Add a server to a sharing group.
    pub fn add_server_to_sharing_group(&self, sg_id: i64, server_id: i64) -> MispResult<Value> {
        self.rt
            .block_on(self.inner.add_server_to_sharing_group(sg_id, server_id))
    }

    /// Remove a server from a sharing group.
    pub fn remove_server_from_sharing_group(
        &self,
        sg_id: i64,
        server_id: i64,
    ) -> MispResult<Value> {
        self.rt.block_on(
            self.inner
                .remove_server_from_sharing_group(sg_id, server_id),
        )
    }

    // ── User Settings ─────────────────────────────────────────────────

    /// List all user settings.
    pub fn user_settings(&self) -> MispResult<Vec<MispUserSetting>> {
        self.rt.block_on(self.inner.user_settings())
    }

    /// Get a specific user setting by key.
    pub fn get_user_setting(
        &self,
        setting: &str,
        user_id: Option<i64>,
    ) -> MispResult<MispUserSetting> {
        self.rt
            .block_on(self.inner.get_user_setting(setting, user_id))
    }

    /// Set a user setting.
    pub fn set_user_setting(
        &self,
        setting: &str,
        value: &Value,
        user_id: Option<i64>,
    ) -> MispResult<Value> {
        self.rt
            .block_on(self.inner.set_user_setting(setting, value, user_id))
    }

    /// Delete a user setting.
    pub fn delete_user_setting(&self, setting: &str, user_id: Option<i64>) -> MispResult<Value> {
        self.rt
            .block_on(self.inner.delete_user_setting(setting, user_id))
    }

    // ── Search ────────────────────────────────────────────────────────

    /// Search MISP using the REST search API.
    pub fn search(
        &self,
        controller: SearchController,
        params: &SearchParameters,
    ) -> MispResult<Value> {
        self.rt.block_on(self.inner.search(controller, params))
    }

    /// Search the event index with filter parameters.
    pub fn search_index(&self, params: &SearchParameters) -> MispResult<Vec<MispEvent>> {
        self.rt.block_on(self.inner.search_index(params))
    }

    /// Search sightings with various filter parameters.
    #[allow(clippy::too_many_arguments)]
    pub fn search_sightings(
        &self,
        context: &str,
        id: i64,
        source: Option<&str>,
        type_sighting: Option<i64>,
        date_from: Option<&str>,
        date_to: Option<&str>,
        publish_timestamp: Option<&str>,
        last: Option<&str>,
        org: Option<&str>,
    ) -> MispResult<Value> {
        self.rt.block_on(self.inner.search_sightings(
            context,
            id,
            source,
            type_sighting,
            date_from,
            date_to,
            publish_timestamp,
            last,
            org,
        ))
    }

    /// Search admin logs with various filter parameters.
    #[allow(clippy::too_many_arguments)]
    pub fn search_logs(
        &self,
        limit: Option<i64>,
        page: Option<i64>,
        log_id: Option<i64>,
        title: Option<&str>,
        created: Option<&str>,
        model: Option<&str>,
        action: Option<&str>,
        user_id: Option<i64>,
        change: Option<&str>,
        email: Option<&str>,
        org: Option<&str>,
        description: Option<&str>,
        ip: Option<&str>,
    ) -> MispResult<Value> {
        self.rt.block_on(self.inner.search_logs(
            limit,
            page,
            log_id,
            title,
            created,
            model,
            action,
            user_id,
            change,
            email,
            org,
            description,
            ip,
        ))
    }

    /// Search feed caches for a specific value.
    pub fn search_feeds(&self, value: &str) -> MispResult<Value> {
        self.rt.block_on(self.inner.search_feeds(value))
    }

    // ── Advanced Features ─────────────────────────────────────────────

    /// Import free-text indicators into an event.
    pub fn freetext(
        &self,
        event_id: i64,
        string: &str,
        adhering_to_warninglists: Option<bool>,
        distribution: Option<i64>,
        sharing_group_id: Option<i64>,
    ) -> MispResult<Value> {
        self.rt.block_on(self.inner.freetext(
            event_id,
            string,
            adhering_to_warninglists,
            distribution,
            sharing_group_id,
        ))
    }

    /// Upload a STIX file to create/update events.
    pub fn upload_stix(&self, data: &str, version: u8) -> MispResult<Value> {
        self.rt.block_on(self.inner.upload_stix(data, version))
    }

    /// Make a raw API call to any MISP endpoint.
    pub fn direct_call(&self, relative_path: &str, data: Option<&Value>) -> MispResult<Value> {
        self.rt
            .block_on(self.inner.direct_call(relative_path, data))
    }

    /// Push an event to ZMQ.
    pub fn push_event_to_zmq(&self, id: i64) -> MispResult<Value> {
        self.rt.block_on(self.inner.push_event_to_zmq(id))
    }

    /// Change the sharing group on an entity.
    pub fn change_sharing_group_on_entity(
        &self,
        entity_uuid: &str,
        sharing_group_id: i64,
        entity_type: &str,
    ) -> MispResult<Value> {
        self.rt.block_on(self.inner.change_sharing_group_on_entity(
            entity_uuid,
            sharing_group_id,
            entity_type,
        ))
    }

    /// Get attribute type/category statistics.
    pub fn attributes_statistics(
        &self,
        context: Option<&str>,
        percentage: Option<bool>,
    ) -> MispResult<Value> {
        self.rt
            .block_on(self.inner.attributes_statistics(context, percentage))
    }

    /// Get tag statistics.
    pub fn tags_statistics(
        &self,
        percentage: Option<bool>,
        name_sort: Option<bool>,
    ) -> MispResult<Value> {
        self.rt
            .block_on(self.inner.tags_statistics(percentage, name_sort))
    }

    /// Get user statistics.
    pub fn users_statistics(&self, context: Option<&str>) -> MispResult<Value> {
        self.rt.block_on(self.inner.users_statistics(context))
    }

    // ── Blocklists ────────────────────────────────────────────────────

    /// List all event blocklist entries.
    pub fn event_blocklists(&self) -> MispResult<Vec<MispEventBlocklist>> {
        self.rt.block_on(self.inner.event_blocklists())
    }

    /// List all organisation blocklist entries.
    pub fn organisation_blocklists(&self) -> MispResult<Vec<MispOrganisationBlocklist>> {
        self.rt.block_on(self.inner.organisation_blocklists())
    }

    /// Add event UUIDs to the blocklist.
    pub fn add_event_blocklist(
        &self,
        uuids: &[&str],
        comment: Option<&str>,
        event_info: Option<&str>,
        event_orgc: Option<&str>,
    ) -> MispResult<Value> {
        self.rt.block_on(
            self.inner
                .add_event_blocklist(uuids, comment, event_info, event_orgc),
        )
    }

    /// Add organisation UUIDs to the blocklist.
    pub fn add_organisation_blocklist(
        &self,
        uuids: &[&str],
        comment: Option<&str>,
        org_name: Option<&str>,
    ) -> MispResult<Value> {
        self.rt.block_on(
            self.inner
                .add_organisation_blocklist(uuids, comment, org_name),
        )
    }

    /// Update an event blocklist entry.
    pub fn update_event_blocklist(&self, blocklist: &MispEventBlocklist) -> MispResult<Value> {
        self.rt
            .block_on(self.inner.update_event_blocklist(blocklist))
    }

    /// Update an organisation blocklist entry.
    pub fn update_organisation_blocklist(
        &self,
        blocklist: &MispOrganisationBlocklist,
    ) -> MispResult<Value> {
        self.rt
            .block_on(self.inner.update_organisation_blocklist(blocklist))
    }

    /// Delete an event blocklist entry.
    pub fn delete_event_blocklist(&self, id: i64) -> MispResult<Value> {
        self.rt.block_on(self.inner.delete_event_blocklist(id))
    }

    /// Delete an organisation blocklist entry.
    pub fn delete_organisation_blocklist(&self, id: i64) -> MispResult<Value> {
        self.rt
            .block_on(self.inner.delete_organisation_blocklist(id))
    }

    // ── Communities ───────────────────────────────────────────────────

    /// List all communities.
    pub fn communities(&self) -> MispResult<Vec<MispCommunity>> {
        self.rt.block_on(self.inner.communities())
    }

    /// Get a specific community by ID.
    pub fn get_community(&self, id: i64) -> MispResult<MispCommunity> {
        self.rt.block_on(self.inner.get_community(id))
    }

    /// Request access to a community.
    #[allow(clippy::too_many_arguments)]
    pub fn request_community_access(
        &self,
        id: i64,
        requestor_org: Option<&str>,
        requestor_email: Option<&str>,
        message: Option<&str>,
        sync: Option<bool>,
        anonymise: Option<bool>,
        mock: Option<bool>,
    ) -> MispResult<Value> {
        self.rt.block_on(self.inner.request_community_access(
            id,
            requestor_org,
            requestor_email,
            message,
            sync,
            anonymise,
            mock,
        ))
    }

    // ── Event Delegations ─────────────────────────────────────────────

    /// List all event delegations.
    pub fn event_delegations(&self) -> MispResult<Vec<MispEventDelegation>> {
        self.rt.block_on(self.inner.event_delegations())
    }

    /// Accept an event delegation.
    pub fn accept_event_delegation(&self, id: i64) -> MispResult<Value> {
        self.rt.block_on(self.inner.accept_event_delegation(id))
    }

    /// Discard (reject) an event delegation.
    pub fn discard_event_delegation(&self, id: i64) -> MispResult<Value> {
        self.rt.block_on(self.inner.discard_event_delegation(id))
    }

    /// Delegate an event to another organisation.
    pub fn delegate_event(
        &self,
        event_id: i64,
        org_id: i64,
        distribution: Option<i64>,
        message: Option<&str>,
    ) -> MispResult<Value> {
        self.rt.block_on(
            self.inner
                .delegate_event(event_id, org_id, distribution, message),
        )
    }
}

/// Register a new user on a MISP instance (unauthenticated, blocking).
///
/// This is a standalone function that does not require an API key.
#[allow(clippy::too_many_arguments)]
pub fn register_user_blocking(
    misp_url: impl Into<String>,
    email: impl Into<String>,
    organisation: Option<&str>,
    org_id: Option<i64>,
    org_name: Option<&str>,
    message: Option<&str>,
    custom_perms: Option<&str>,
    perm_sync: bool,
    perm_publish: bool,
    perm_admin: bool,
    verify_ssl: bool,
) -> MispResult<Value> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| MispError::InvalidInput(format!("Failed to create runtime: {e}")))?;
    rt.block_on(crate::client::register_user(
        misp_url,
        email,
        organisation,
        org_id,
        org_name,
        message,
        custom_perms,
        perm_sync,
        perm_publish,
        perm_admin,
        verify_ssl,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_partial_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Helper: start a wiremock server on a background multi-threaded runtime
    /// so the blocking client's own single-threaded runtime can reach it.
    struct MockEnv {
        _rt: tokio::runtime::Runtime,
        server: MockServer,
    }

    impl MockEnv {
        fn new() -> Self {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let server = rt.block_on(MockServer::start());
            Self { _rt: rt, server }
        }

        fn mount(&self, mock: Mock) {
            self._rt.block_on(mock.mount(&self.server));
        }

        fn client(&self) -> MispClientBlocking {
            self.client_with_key("test-api-key")
        }

        fn client_with_key(&self, key: &str) -> MispClientBlocking {
            MispClientBlocking::new(self.server.uri(), key, false).unwrap()
        }
    }

    // ── Construction tests ───────────────────────────────────────────

    #[test]
    fn test_blocking_client_construction() {
        let client = MispClientBlocking::new("https://misp.example.com", "test-key", false);
        assert!(client.is_ok());
        let client = client.unwrap();
        assert_eq!(client.base_url().as_str(), "https://misp.example.com/");
    }

    #[test]
    fn test_blocking_client_invalid_url() {
        let client = MispClientBlocking::new("not a url :::", "key", true);
        assert!(client.is_err());
    }

    #[test]
    fn test_blocking_client_builder() {
        let client = MispClientBlocking::builder("https://misp.example.com", "test-key")
            .ssl_verify(false)
            .timeout(Duration::from_secs(30))
            .header("X-Custom", "value")
            .build();
        assert!(client.is_ok());
    }

    #[test]
    fn test_blocking_client_debug() {
        let client =
            MispClientBlocking::new("https://misp.example.com", "test-key", false).unwrap();
        let debug = format!("{:?}", client);
        assert!(debug.contains("MispClientBlocking"));
    }

    #[test]
    fn test_blocking_describe_types_local() {
        let client =
            MispClientBlocking::new("https://misp.example.com", "test-key", false).unwrap();
        let result = client.describe_types_local();
        assert!(result.is_ok());
        let json = result.unwrap();
        assert!(json.get("result").is_some());
    }

    #[test]
    fn test_blocking_inner_accessor() {
        let client =
            MispClientBlocking::new("https://misp.example.com", "test-key", false).unwrap();
        let inner = client.inner();
        assert_eq!(inner.base_url().as_str(), "https://misp.example.com/");
    }

    // ── Auth & error handling tests ──────────────────────────────────

    #[test]
    fn test_blocking_auth_header_sent() {
        let env = MockEnv::new();

        env.mount(
            Mock::given(method("GET"))
                .and(header("Authorization", "my-secret-key"))
                .and(header("Accept", "application/json"))
                .and(header("Content-Type", "application/json"))
                .respond_with(
                    ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true})),
                ),
        );

        let client = env.client_with_key("my-secret-key");
        let result = client.misp_instance_version();
        // The mock matches on the Authorization header; if it didn't match we'd get an error.
        // misp_instance_version hits /servers/getVersion which won't match the mock path,
        // so let's use describe_types_remote instead or test via a more general endpoint.
        // Actually, the mock has no path constraint so it matches any GET.
        assert!(result.is_ok());
    }

    #[test]
    fn test_blocking_auth_error() {
        let env = MockEnv::new();

        env.mount(
            Mock::given(method("GET"))
                .respond_with(ResponseTemplate::new(403).set_body_string("Forbidden")),
        );

        let client = env.client();
        let result = client.misp_instance_version();
        assert!(matches!(result, Err(MispError::AuthError(_))));
    }

    #[test]
    fn test_blocking_not_found_error() {
        let env = MockEnv::new();

        env.mount(
            Mock::given(method("GET"))
                .respond_with(ResponseTemplate::new(404).set_body_string("Not found")),
        );

        let client = env.client();
        let result = client.describe_types_remote();
        assert!(matches!(result, Err(MispError::NotFound(_))));
    }

    #[test]
    fn test_blocking_api_error() {
        let env = MockEnv::new();

        env.mount(
            Mock::given(method("GET")).respond_with(
                ResponseTemplate::new(500)
                    .set_body_json(serde_json::json!({"message": "Internal error"})),
            ),
        );

        let client = env.client();
        let result = client.misp_instance_version();
        match result {
            Err(MispError::ApiError { status, message }) => {
                assert_eq!(status, 500);
                assert_eq!(message, "Internal error");
            }
            other => panic!("Expected ApiError, got {:?}", other),
        }
    }

    // ── Server info tests ────────────────────────────────────────────

    #[test]
    fn test_blocking_misp_instance_version() {
        let env = MockEnv::new();

        env.mount(
            Mock::given(method("GET"))
                .and(path("/servers/getVersion"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "version": "2.4.180",
                    "perm_sync": false,
                    "perm_sighting": false
                }))),
        );

        let client = env.client();
        let result = client.misp_instance_version().unwrap();
        assert_eq!(result["version"], "2.4.180");
    }

    // ── Event CRUD tests ─────────────────────────────────────────────

    #[test]
    fn test_blocking_get_event() {
        let env = MockEnv::new();

        env.mount(
            Mock::given(method("GET"))
                .and(path("/events/view/42"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "Event": {
                        "id": "42",
                        "info": "Test Event",
                        "published": false,
                        "date": "2024-01-15",
                        "threat_level_id": "2",
                        "analysis": "1",
                        "distribution": "0"
                    }
                }))),
        );

        let client = env.client();
        let event = client.get_event(42).unwrap();
        assert_eq!(event.id, Some(42));
        assert_eq!(event.info, "Test Event");
        assert!(!event.published);
        assert_eq!(event.threat_level_id, Some(2));
    }

    #[test]
    fn test_blocking_add_event() {
        let env = MockEnv::new();

        env.mount(
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
                }))),
        );

        let client = env.client();
        let event = crate::MispEvent::new("New event");
        let result = client.add_event(&event).unwrap();
        assert_eq!(result.id, Some(99));
        assert_eq!(result.info, "New event");
    }

    #[test]
    fn test_blocking_event_exists() {
        let env = MockEnv::new();

        env.mount(
            Mock::given(method("HEAD"))
                .and(path("/events/view/1"))
                .respond_with(ResponseTemplate::new(200)),
        );

        let client = env.client();
        assert!(client.event_exists(1).unwrap());
    }

    #[test]
    fn test_blocking_event_not_exists() {
        let env = MockEnv::new();

        env.mount(
            Mock::given(method("HEAD"))
                .and(path("/events/view/999"))
                .respond_with(ResponseTemplate::new(404)),
        );

        let client = env.client();
        assert!(!client.event_exists(999).unwrap());
    }

    #[test]
    fn test_blocking_delete_event() {
        let env = MockEnv::new();

        env.mount(
            Mock::given(method("POST"))
                .and(path("/events/delete/42"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_json(serde_json::json!({"message": "Event deleted."})),
                ),
        );

        let client = env.client();
        let result = client.delete_event(42).unwrap();
        assert_eq!(result["message"], "Event deleted.");
    }

    #[test]
    fn test_blocking_events_list() {
        let env = MockEnv::new();

        env.mount(
            Mock::given(method("GET"))
                .and(path("/events/index"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                    {"id": "1", "info": "Event A", "published": true},
                    {"id": "2", "info": "Event B", "published": false}
                ]))),
        );

        let client = env.client();
        let events = client.events().unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].info, "Event A");
        assert_eq!(events[1].info, "Event B");
    }

    #[test]
    fn test_blocking_publish_with_alert() {
        let env = MockEnv::new();

        env.mount(
            Mock::given(method("POST"))
                .and(path("/events/alert/5"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_json(serde_json::json!({"saved": true, "success": true})),
                ),
        );

        let client = env.client();
        let result = client.publish(5, true).unwrap();
        assert_eq!(result["saved"], true);
    }

    #[test]
    fn test_blocking_publish_without_alert() {
        let env = MockEnv::new();

        env.mount(
            Mock::given(method("POST"))
                .and(path("/events/publish/5"))
                .respond_with(
                    ResponseTemplate::new(200).set_body_json(serde_json::json!({"saved": true})),
                ),
        );

        let client = env.client();
        let result = client.publish(5, false).unwrap();
        assert_eq!(result["saved"], true);
    }

    // ── Attribute CRUD tests ─────────────────────────────────────────

    #[test]
    fn test_blocking_get_attribute() {
        let env = MockEnv::new();

        env.mount(
            Mock::given(method("GET"))
                .and(path("/attributes/view/7"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
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
                }))),
        );

        let client = env.client();
        let attr = client.get_attribute(7).unwrap();
        assert_eq!(attr.id, Some(7));
        assert_eq!(attr.attr_type, "ip-dst");
        assert_eq!(attr.value, "10.0.0.1");
        assert!(attr.to_ids);
    }

    #[test]
    fn test_blocking_add_attribute() {
        let env = MockEnv::new();

        env.mount(
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
                }))),
        );

        let client = env.client();
        let attr = crate::MispAttribute::new("domain", "Network activity", "evil.com");
        let result = client.add_attribute(3, &attr).unwrap();
        assert_eq!(result.id, Some(100));
        assert_eq!(result.value, "evil.com");
    }

    #[test]
    fn test_blocking_delete_attribute_hard() {
        let env = MockEnv::new();

        env.mount(
            Mock::given(method("POST"))
                .and(path("/attributes/delete/50"))
                .and(body_partial_json(serde_json::json!({"hard_delete": 1})))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_json(serde_json::json!({"message": "Attribute deleted."})),
                ),
        );

        let client = env.client();
        let result = client.delete_attribute(50, true).unwrap();
        assert_eq!(result["message"], "Attribute deleted.");
    }

    // ── Tag tests ────────────────────────────────────────────────────

    #[test]
    fn test_blocking_tags_list() {
        let env = MockEnv::new();

        env.mount(
            Mock::given(method("GET"))
                .and(path("/tags/index"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "Tag": [
                        {"id": "1", "name": "tlp:white", "colour": "#ffffff"},
                        {"id": "2", "name": "tlp:green", "colour": "#00ff00"}
                    ]
                }))),
        );

        let client = env.client();
        let tags = client.tags().unwrap();
        assert_eq!(tags.len(), 2);
        assert_eq!(tags[0].name, "tlp:white");
    }

    #[test]
    fn test_blocking_search_tags() {
        let env = MockEnv::new();

        env.mount(
            Mock::given(method("GET"))
                .and(path("/tags/search/tlp"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                    {"id": "1", "name": "tlp:white"},
                    {"id": "2", "name": "tlp:green"}
                ]))),
        );

        let client = env.client();
        let result = client.search_tags("tlp", false).unwrap();
        assert_eq!(result.len(), 2);
    }
}
