# RustMISP — Product Requirements Document

## 1. Overview

RustMISP is a Rust client library for the MISP (Malware Information Sharing Platform) REST API, providing feature parity with [PyMISP](https://github.com/MISP/PyMISP) (v2.5.32.2). It offers strongly-typed data models, an ergonomic API client, and the same breadth of functionality that Python users enjoy — with the performance, safety, and concurrency benefits of Rust.

RustMISP is maintained as a **standalone Git repository** (e.g., `github.com/MISP/RustMISP`) and included in the main MISP repository as a **Git submodule**, following the same pattern as PyMISP and other MISP sub-projects (misp-galaxy, misp-taxonomies, etc.).

### Goals

- **Full feature parity** with PyMISP's public API surface (~243 methods)
- **Strongly-typed data models** for all 30+ MISP entity types
- **Serde-based serialization** (JSON) matching MISP's wire format exactly
- **Async-first** design using `tokio` + `reqwest`, with optional blocking wrapper
- **Idiomatic Rust** — Result-based error handling, builder patterns, enums for fixed sets
- **Reuse PyMISP's existing Python test suite** for integration testing against a live MISP instance

---

## 2. Repository & Integration

RustMISP follows the same model as PyMISP:

- **Standalone repository**: `github.com/MISP/RustMISP` with its own branches, tags, releases, and CI
- **Git submodule in MISP**: Referenced in MISP's `.gitmodules` at path `RustMISP/`, branch `main`
- **Independent versioning**: Uses its own semver (starting at `0.1.0`), not tied to MISP's release cycle
- **Own CI/CD**: GitHub Actions for `cargo test`, `cargo clippy`, `cargo fmt --check`, and integration tests
- **crates.io publishing**: Published as the `rustmisp` crate (when ready for public consumption)

### Submodule setup in MISP

```
# In the MISP repository:
git submodule add -b main https://github.com/MISP/RustMISP.git RustMISP
```

This means:
- RustMISP development happens in its own repo with its own commit history
- MISP pins a specific RustMISP commit via the submodule pointer
- Updating RustMISP in MISP is: `cd RustMISP && git pull origin main && cd .. && git add RustMISP && git commit`
- Contributors can clone RustMISP independently without needing the full MISP repo

---

## 3. Architecture

```
RustMISP/                        # ← standalone git repository root
├── .github/
│   └── workflows/
│       ├── ci.yml               # cargo test, clippy, fmt on PR/push
│       └── release.yml          # crates.io publish on tag
├── .gitignore
├── LICENSE                      # Same license as MISP (AGPL-3.0)
├── README.md
├── CHANGELOG.md
├── Cargo.toml
├── src/
│   ├── lib.rs                  # Public re-exports
│   ├── client.rs               # MispClient (async API client)
│   ├── client_blocking.rs      # Blocking wrapper
│   ├── error.rs                # Error types
│   ├── models/                 # Data model structs
│   │   ├── mod.rs
│   │   ├── event.rs            # MispEvent
│   │   ├── attribute.rs        # MispAttribute
│   │   ├── object.rs           # MispObject, MispObjectReference
│   │   ├── tag.rs              # MispTag
│   │   ├── organisation.rs     # MispOrganisation
│   │   ├── user.rs             # MispUser, MispRole
│   │   ├── server.rs           # MispServer
│   │   ├── feed.rs             # MispFeed
│   │   ├── sharing_group.rs    # MispSharingGroup
│   │   ├── sighting.rs         # MispSighting
│   │   ├── taxonomy.rs         # MispTaxonomy
│   │   ├── warninglist.rs      # MispWarninglist
│   │   ├── noticelist.rs       # MispNoticelist
│   │   ├── galaxy.rs           # MispGalaxy, MispGalaxyCluster, MispGalaxyClusterElement, MispGalaxyClusterRelation
│   │   ├── analyst_data.rs     # MispNote, MispOpinion, MispRelationship
│   │   ├── shadow_attribute.rs # MispShadowAttribute (proposals)
│   │   ├── event_report.rs     # MispEventReport
│   │   ├── event_delegation.rs # MispEventDelegation
│   │   ├── blocklist.rs        # MispEventBlocklist, MispOrganisationBlocklist
│   │   ├── correlation.rs      # MispCorrelationExclusion, MispDecayingModel
│   │   ├── community.rs        # MispCommunity
│   │   ├── user_setting.rs     # MispUserSetting
│   │   ├── inbox.rs            # MispInbox
│   │   ├── log.rs              # MispLog
│   │   ├── object_template.rs  # MispObjectTemplate
│   │   └── enums.rs            # Distribution, ThreatLevel, Analysis
│   ├── search.rs               # SearchBuilder, SearchParameters
│   ├── tools/                  # Optional tool modules (feature-gated)
│   │   ├── mod.rs
│   │   ├── file_object.rs      # FileObject generator
│   │   ├── generic_object.rs   # GenericObjectGenerator
│   │   ├── csv_loader.rs       # CSV → attributes
│   │   ├── openioc.rs          # OpenIOC import
│   │   └── feed_generator.rs   # Feed meta generator
│   └── validation.rs           # Attribute type/category validation from describeTypes.json
├── data/
│   └── describeTypes.json      # Bundled MISP schema (copied from PyMISP)
├── tests/
│   ├── unit/                   # Rust unit tests
│   │   ├── mod.rs
│   │   ├── test_models.rs
│   │   ├── test_search.rs
│   │   └── test_validation.rs
│   ├── integration/            # Rust integration tests (against live MISP)
│   │   └── mod.rs
│   └── python/                 # PyMISP test suite (copied from PyMISP/tests/)
│       ├── test_mispevent.py
│       ├── test_analyst_data.py
│       ├── test_fileobject.py
│       ├── test_emailobject.py
│       ├── test_attributevalidationtool.py
│       ├── test_reportlab.py
│       ├── testlive_comprehensive.py
│       ├── testlive_local.py
│       ├── testlive_sync.py
│       └── (all test data files)
└── examples/
    ├── basic_event.rs          # Create and publish an event
    ├── search_attributes.rs    # Search with complex queries
    ├── manage_tags.rs          # Tag operations
    └── feed_operations.rs      # Feed management
```

---

## 4. Data Models

All models derive `Serialize`, `Deserialize`, `Debug`, `Clone`, `Default`. Fields use `Option<T>` for optional API fields. Each model implements `From<serde_json::Value>` for raw dict-like access when needed.

### 4.1 Core Enums

| Enum | Variants | PyMISP equivalent |
|------|----------|-------------------|
| `Distribution` | `YourOrgOnly(0)`, `ThisCommunity(1)`, `ConnectedCommunities(2)`, `AllCommunities(3)`, `SharingGroup(4)`, `InheritEvent(5)` | `Distribution` |
| `ThreatLevel` | `High(1)`, `Medium(2)`, `Low(3)`, `Undefined(4)` | `ThreatLevel` |
| `Analysis` | `Initial(0)`, `Ongoing(1)`, `Complete(2)` | `Analysis` |

### 4.2 Entity Structs (30+)

Each struct maps 1:1 to the corresponding PyMISP class:

| Rust Struct | PyMISP Class | Key Fields |
|-------------|-------------|------------|
| `MispEvent` | `MISPEvent` | id, uuid, info, date, threat_level_id, analysis, distribution, attributes, objects, tags, galaxies, event_reports, org, orgc |
| `MispAttribute` | `MISPAttribute` | id, uuid, event_id, type_, category, value, to_ids, distribution, comment, data (attachment base64), first_seen, last_seen, tags, sightings, shadow_attributes |
| `MispObject` | `MISPObject` | id, uuid, name, template_uuid, template_version, attributes, references, distribution |
| `MispObjectReference` | `MISPObjectReference` | id, uuid, source_uuid, referenced_uuid, relationship_type, comment |
| `MispObjectAttribute` | `MISPObjectAttribute` | Same as MispAttribute + object_relation |
| `MispTag` | `MISPTag` | id, name, colour, exportable, org_id, user_id, local |
| `MispOrganisation` | `MISPOrganisation` | id, uuid, name, description, nationality, sector, type_, contacts |
| `MispUser` | `MISPUser` | id, email, org_id, role_id, authkey, invited_by, gpgkey, nids_sid, termsaccepted, autoalert, contactalert, disabled |
| `MispRole` | `MISPRole` | id, name, perm_* (multiple permission booleans) |
| `MispServer` | `MISPServer` | id, url, name, authkey, org_id, push, pull, push_sightings, push_galaxy_clusters, remote_org_id |
| `MispFeed` | `MISPFeed` | id, name, provider, url, source_format, enabled, caching_enabled, distribution, rules, headers |
| `MispSharingGroup` | `MISPSharingGroup` | id, uuid, name, description, releasability, organisation_uuid, active, roaming, sharing_group_org, sharing_group_server |
| `MispSighting` | `MISPSighting` | id, attribute_id, event_id, org_id, date_sighting, uuid, source, type_ (0=sighting, 1=false-positive, 2=expiration) |
| `MispTaxonomy` | `MISPTaxonomy` | id, namespace, description, version, enabled, exclusive, required |
| `MispWarninglist` | `MISPWarninglist` | id, name, type_, description, version, enabled, warninglist_entry_count |
| `MispNoticelist` | `MISPNoticelist` | id, name, expanded_name, ref, geographical_area, version, enabled |
| `MispGalaxy` | `MISPGalaxy` | id, uuid, name, type_, description, version, namespace, galaxy_clusters |
| `MispGalaxyCluster` | `MISPGalaxyCluster` | id, uuid, type_, value, tag_name, description, source, authors, galaxy_cluster_elements, galaxy_cluster_relations |
| `MispGalaxyClusterElement` | `MISPGalaxyClusterElement` | id, galaxy_cluster_id, key, value |
| `MispGalaxyClusterRelation` | `MISPGalaxyClusterRelation` | id, galaxy_cluster_id, referenced_galaxy_cluster_id, referenced_galaxy_cluster_uuid, distribution, relationship_type, tags |
| `MispNote` | `MISPNote` | id, uuid, body, language, note, object_uuid, object_type, authors, created, modified |
| `MispOpinion` | `MISPOpinion` | id, uuid, opinion (0-100), comment, object_uuid, object_type, authors, created, modified |
| `MispRelationship` | `MISPRelationship` | id, uuid, relationship_type, related_object_uuid, related_object_type, object_uuid, object_type |
| `MispShadowAttribute` | `MISPShadowAttribute` | id, uuid, event_id, old_id, type_, category, value, to_ids, proposal_to_delete |
| `MispEventReport` | `MISPEventReport` | id, uuid, event_id, name, content, distribution |
| `MispEventDelegation` | `MISPEventDelegation` | id, event_id, org_id, requester_org_id, message, distribution |
| `MispEventBlocklist` | `MISPEventBlocklist` | id, event_uuid, event_orgc, event_info, comment |
| `MispOrganisationBlocklist` | `MISPOrganisationBlocklist` | id, org_uuid, org_name, comment |
| `MispCorrelationExclusion` | `MISPCorrelationExclusion` | id, value, comment |
| `MispDecayingModel` | `MISPDecayingModel` | id, name, parameters, attribute_types, description, org_id, enabled |
| `MispCommunity` | `MISPCommunity` | id, uuid, name, description, url, sector, nationality, type_, org |
| `MispUserSetting` | `MISPUserSetting` | id, setting, value, user_id |
| `MispInbox` | `MISPInbox` | id, type_, title, ip, user_agent, email, org, data, comment |
| `MispLog` | `MISPLog` | id, title, created, model, model_id, action, user_id, change, email, org, description, ip |
| `MispObjectTemplate` | `MISPObjectTemplate` | id, uuid, name, version, description, meta_category, attributes |

---

## 5. API Client Methods

The `MispClient` struct provides all ~243 methods from PyMISP's `PyMISP` class. Methods are grouped into the same logical categories.

### 5.1 Constructor & Configuration

| Method | Description |
|--------|-------------|
| `MispClient::new(url, key, ssl_verify)` | Create client with API key |
| `MispClient::builder()` | Builder pattern for advanced config (proxy, timeout, custom headers, client cert, TLS CA bundle) |
| `toggle_global_pythonify()` *(N/A — Rust always returns typed structs)* | — |

### 5.2 Server / Instance Info

| Method | PyMISP equivalent |
|--------|-------------------|
| `describe_types_local()` | `describe_types_local` |
| `describe_types_remote()` | `describe_types_remote` |
| `misp_instance_version()` | `misp_instance_version` |
| `version()` | `version` |
| `recommended_pymisp_version()` | `recommended_pymisp_version` |
| `update_misp()` | `update_misp` |
| `server_settings()` | `server_settings` |
| `get_server_setting(setting)` | `get_server_setting` |
| `set_server_setting(setting, value, force)` | `set_server_setting` |
| `remote_acl(debug_type)` | `remote_acl` |
| `db_schema_diagnostic()` | `db_schema_diagnostic` |
| `restart_workers()` | `restart_workers` |
| `restart_dead_workers()` | `restart_dead_workers` |
| `get_workers()` | `get_workers` |
| `start_worker(worker_type)` | `start_worker` |
| `stop_worker_by_pid(pid)` | `stop_worker_by_pid` |
| `kill_all_workers()` | `kill_all_workers` |

### 5.3 Events (CRUD + Workflow)

| Method | PyMISP equivalent |
|--------|-------------------|
| `events()` | `events` |
| `get_event(id)` | `get_event` |
| `event_exists(id)` | `event_exists` |
| `add_event(event)` | `add_event` |
| `update_event(event)` | `update_event` |
| `delete_event(id)` | `delete_event` |
| `publish(id, alert)` | `publish` |
| `unpublish(id)` | `unpublish` |
| `contact_event_reporter(id, message)` | `contact_event_reporter` |
| `enrich_event(id, modules)` | `enrich_event` |

### 5.4 Event Reports

| Method | PyMISP equivalent |
|--------|-------------------|
| `get_event_report(id)` | `get_event_report` |
| `get_event_reports(event_id)` | `get_event_reports` |
| `add_event_report(event_id, report)` | `add_event_report` |
| `update_event_report(report)` | `update_event_report` |
| `delete_event_report(id, hard)` | `delete_event_report` |

### 5.5 Analyst Data (Notes, Opinions, Relationships)

| Method | PyMISP equivalent |
|--------|-------------------|
| `get_analyst_data(id, data_type)` | `get_analyst_data` |
| `add_analyst_data(data)` | `add_analyst_data` |
| `update_analyst_data(data)` | `update_analyst_data` |
| `delete_analyst_data(data)` | `delete_analyst_data` |
| `get_note(note)` | `get_note` |
| `add_note(note)` | `add_note` |
| `update_note(note)` | `update_note` |
| `delete_note(id)` | `delete_note` |
| `get_opinion(opinion)` | `get_opinion` |
| `add_opinion(opinion)` | `add_opinion` |
| `update_opinion(opinion)` | `update_opinion` |
| `delete_opinion(id)` | `delete_opinion` |
| `get_relationship(rel)` | `get_relationship` |
| `add_relationship(rel)` | `add_relationship` |
| `update_relationship(rel)` | `update_relationship` |
| `delete_relationship(id)` | `delete_relationship` |

### 5.6 Attributes

| Method | PyMISP equivalent |
|--------|-------------------|
| `attributes()` | `attributes` |
| `get_attribute(id)` | `get_attribute` |
| `attribute_exists(id)` | `attribute_exists` |
| `add_attribute(event_id, attribute)` | `add_attribute` |
| `update_attribute(attribute)` | `update_attribute` |
| `delete_attribute(id, hard)` | `delete_attribute` |
| `restore_attribute(id)` | `restore_attribute` |
| `enrich_attribute(id, modules)` | `enrich_attribute` |

### 5.7 Attribute Proposals (Shadow Attributes)

| Method | PyMISP equivalent |
|--------|-------------------|
| `attribute_proposals(event_id)` | `attribute_proposals` |
| `get_attribute_proposal(id)` | `get_attribute_proposal` |
| `add_attribute_proposal(event_id, attribute)` | `add_attribute_proposal` |
| `update_attribute_proposal(attr_id, attribute)` | `update_attribute_proposal` |
| `delete_attribute_proposal(id)` | `delete_attribute_proposal` |
| `accept_attribute_proposal(id)` | `accept_attribute_proposal` |
| `discard_attribute_proposal(id)` | `discard_attribute_proposal` |

### 5.8 Objects

| Method | PyMISP equivalent |
|--------|-------------------|
| `get_object(id)` | `get_object` |
| `object_exists(id)` | `object_exists` |
| `add_object(event_id, object)` | `add_object` |
| `update_object(object)` | `update_object` |
| `delete_object(id, hard)` | `delete_object` |
| `add_object_reference(reference)` | `add_object_reference` |
| `delete_object_reference(id)` | `delete_object_reference` |
| `object_templates()` | `object_templates` |
| `get_object_template(id)` | `get_object_template` |
| `get_raw_object_template(uuid_or_name)` | `get_raw_object_template` |
| `update_object_templates()` | `update_object_templates` |

### 5.9 Sightings

| Method | PyMISP equivalent |
|--------|-------------------|
| `sightings(entity)` | `sightings` |
| `add_sighting(sighting, attribute)` | `add_sighting` |
| `delete_sighting(id)` | `delete_sighting` |

### 5.10 Tags

| Method | PyMISP equivalent |
|--------|-------------------|
| `tags()` | `tags` |
| `get_tag(id)` | `get_tag` |
| `add_tag(tag)` | `add_tag` |
| `update_tag(tag)` | `update_tag` |
| `delete_tag(id)` | `delete_tag` |
| `enable_tag(tag)` | `enable_tag` |
| `disable_tag(tag)` | `disable_tag` |
| `search_tags(name, strict)` | `search_tags` |
| `tag(entity, tag, local)` | `tag` |
| `untag(entity, tag)` | `untag` |

### 5.11 Taxonomies

| Method | PyMISP equivalent |
|--------|-------------------|
| `taxonomies()` | `taxonomies` |
| `get_taxonomy(id)` | `get_taxonomy` |
| `enable_taxonomy(id)` | `enable_taxonomy` |
| `disable_taxonomy(id)` | `disable_taxonomy` |
| `enable_taxonomy_tags(id)` | `enable_taxonomy_tags` |
| `disable_taxonomy_tags(id)` | `disable_taxonomy_tags` |
| `update_taxonomies()` | `update_taxonomies` |
| `set_taxonomy_required(id, required)` | `set_taxonomy_required` |

### 5.12 Warninglists

| Method | PyMISP equivalent |
|--------|-------------------|
| `warninglists()` | `warninglists` |
| `get_warninglist(id)` | `get_warninglist` |
| `toggle_warninglist(id, name, force_enable)` | `toggle_warninglist` |
| `enable_warninglist(id)` | `enable_warninglist` |
| `disable_warninglist(id)` | `disable_warninglist` |
| `values_in_warninglist(values)` | `values_in_warninglist` |
| `update_warninglists()` | `update_warninglists` |

### 5.13 Noticelists

| Method | PyMISP equivalent |
|--------|-------------------|
| `noticelists()` | `noticelists` |
| `get_noticelist(id)` | `get_noticelist` |
| `enable_noticelist(id)` | `enable_noticelist` |
| `disable_noticelist(id)` | `disable_noticelist` |
| `update_noticelists()` | `update_noticelists` |

### 5.14 Galaxies

| Method | PyMISP equivalent |
|--------|-------------------|
| `galaxies(update)` | `galaxies` |
| `search_galaxy(value)` | `search_galaxy` |
| `get_galaxy(id, with_cluster)` | `get_galaxy` |
| `search_galaxy_clusters(galaxy, context, searchall)` | `search_galaxy_clusters` |
| `update_galaxies()` | `update_galaxies` |
| `get_galaxy_cluster(id)` | `get_galaxy_cluster` |
| `add_galaxy_cluster(galaxy, cluster)` | `add_galaxy_cluster` |
| `update_galaxy_cluster(cluster)` | `update_galaxy_cluster` |
| `publish_galaxy_cluster(id)` | `publish_galaxy_cluster` |
| `fork_galaxy_cluster(galaxy, cluster)` | `fork_galaxy_cluster` |
| `delete_galaxy_cluster(id, hard)` | `delete_galaxy_cluster` |
| `add_galaxy_cluster_relation(relation)` | `add_galaxy_cluster_relation` |
| `update_galaxy_cluster_relation(relation)` | `update_galaxy_cluster_relation` |
| `delete_galaxy_cluster_relation(id)` | `delete_galaxy_cluster_relation` |
| `attach_galaxy_cluster(entity, cluster, local)` | `attach_galaxy_cluster` |

### 5.15 Feeds

| Method | PyMISP equivalent |
|--------|-------------------|
| `feeds()` | `feeds` |
| `get_feed(id)` | `get_feed` |
| `add_feed(feed)` | `add_feed` |
| `update_feed(feed)` | `update_feed` |
| `delete_feed(id)` | `delete_feed` |
| `enable_feed(id)` | `enable_feed` |
| `disable_feed(id)` | `disable_feed` |
| `enable_feed_cache(id)` | `enable_feed_cache` |
| `disable_feed_cache(id)` | `disable_feed_cache` |
| `fetch_feed(id)` | `fetch_feed` |
| `cache_all_feeds()` | `cache_all_feeds` |
| `cache_feed(id)` | `cache_feed` |
| `cache_freetext_feeds()` | `cache_freetext_feeds` |
| `cache_misp_feeds()` | `cache_misp_feeds` |
| `compare_feeds()` | `compare_feeds` |
| `load_default_feeds()` | `load_default_feeds` |
| `search_feeds(value)` | `search_feeds` |

### 5.16 Servers

| Method | PyMISP equivalent |
|--------|-------------------|
| `servers()` | `servers` |
| `get_sync_config()` | `get_sync_config` |
| `import_server(server)` | `import_server` |
| `add_server(server)` | `add_server` |
| `update_server(server)` | `update_server` |
| `delete_server(id)` | `delete_server` |
| `server_pull(id, event)` | `server_pull` |
| `server_push(id, event)` | `server_push` |
| `test_server(id)` | `test_server` |

### 5.17 Sharing Groups

| Method | PyMISP equivalent |
|--------|-------------------|
| `sharing_groups()` | `sharing_groups` |
| `get_sharing_group(id)` | `get_sharing_group` |
| `add_sharing_group(sg)` | `add_sharing_group` |
| `update_sharing_group(sg)` | `update_sharing_group` |
| `sharing_group_exists(id)` | `sharing_group_exists` |
| `delete_sharing_group(id)` | `delete_sharing_group` |
| `add_org_to_sharing_group(sg, org)` | `add_org_to_sharing_group` |
| `remove_org_from_sharing_group(sg, org)` | `remove_org_from_sharing_group` |
| `add_server_to_sharing_group(sg, server)` | `add_server_to_sharing_group` |
| `remove_server_from_sharing_group(sg, server)` | `remove_server_from_sharing_group` |

### 5.18 Organisations

| Method | PyMISP equivalent |
|--------|-------------------|
| `organisations(scope, search)` | `organisations` |
| `get_organisation(id)` | `get_organisation` |
| `organisation_exists(id)` | `organisation_exists` |
| `add_organisation(org)` | `add_organisation` |
| `update_organisation(org)` | `update_organisation` |
| `delete_organisation(id)` | `delete_organisation` |

### 5.19 Users

| Method | PyMISP equivalent |
|--------|-------------------|
| `users(search, organisation)` | `users` |
| `get_user(id)` | `get_user` |
| `get_new_authkey(user)` | `get_new_authkey` |
| `add_user(user)` | `add_user` |
| `update_user(user)` | `update_user` |
| `delete_user(id)` | `delete_user` |
| `change_user_password(password)` | `change_user_password` |
| `user_registrations()` | `user_registrations` |
| `accept_user_registration(id, org, role, perm_sync, perm_publish, perm_admin)` | `accept_user_registration` |
| `discard_user_registration(id)` | `discard_user_registration` |
| `users_heartbeat()` | `users_heartbeat` |

### 5.20 Roles

| Method | PyMISP equivalent |
|--------|-------------------|
| `roles()` | `roles` |
| `add_role(role)` | `add_role` |
| `update_role(role)` | `update_role` |
| `set_default_role(id)` | `set_default_role` |
| `delete_role(id)` | `delete_role` |

### 5.21 Correlation Exclusions

| Method | PyMISP equivalent |
|--------|-------------------|
| `correlation_exclusions()` | `correlation_exclusions` |
| `get_correlation_exclusion(id)` | `get_correlation_exclusion` |
| `add_correlation_exclusion(exclusion)` | `add_correlation_exclusion` |
| `delete_correlation_exclusion(id)` | `delete_correlation_exclusion` |
| `clean_correlation_exclusions()` | `clean_correlation_exclusions` |

### 5.22 Decaying Models

| Method | PyMISP equivalent |
|--------|-------------------|
| `update_decaying_models()` | `update_decaying_models` |
| `decaying_models()` | `decaying_models` |
| `enable_decaying_model(id)` | `enable_decaying_model` |
| `disable_decaying_model(id)` | `disable_decaying_model` |

### 5.23 Search (Complex Queries)

| Method | PyMISP equivalent |
|--------|-------------------|
| `search(controller, params)` | `search` — supports 50+ parameters: value, type_attribute, category, org, tags, date_from/to, last, event_id, uuid, publish_timestamp, timestamp, enforceWarninglist, to_ids, deleted, include_* flags, etc. |
| `search_index(params)` | `search_index` |
| `search_sightings(context, source, type_, date_from, date_to, publish_timestamp, last, org, id)` | `search_sightings` |
| `search_logs(limit, page, log_id, title, created, model, action, user_id, change, email, org, description, ip)` | `search_logs` |
| `build_complex_query(or_params, and_params, not_params)` | `build_complex_query` |

### 5.24 User Settings

| Method | PyMISP equivalent |
|--------|-------------------|
| `user_settings()` | `user_settings` |
| `get_user_setting(setting, user)` | `get_user_setting` |
| `set_user_setting(setting, value, user)` | `set_user_setting` |
| `delete_user_setting(setting, user)` | `delete_user_setting` |

### 5.25 Blocklists

| Method | PyMISP equivalent |
|--------|-------------------|
| `event_blocklists()` | `event_blocklists` |
| `organisation_blocklists()` | `organisation_blocklists` |
| `add_event_blocklist(uuids, comment, event_info, event_orgc)` | `add_event_blocklist` |
| `add_organisation_blocklist(uuids, comment, org_name)` | `add_organisation_blocklist` |
| `update_event_blocklist(blocklist)` | `update_event_blocklist` |
| `update_organisation_blocklist(blocklist)` | `update_organisation_blocklist` |
| `delete_event_blocklist(id)` | `delete_event_blocklist` |
| `delete_organisation_blocklist(id)` | `delete_organisation_blocklist` |

### 5.26 Communities

| Method | PyMISP equivalent |
|--------|-------------------|
| `communities()` | `communities` |
| `get_community(id)` | `get_community` |
| `request_community_access(id, requestor_org, requestor_email, message, sync, anonymise, mock)` | `request_community_access` |

### 5.27 Event Delegations

| Method | PyMISP equivalent |
|--------|-------------------|
| `event_delegations()` | `event_delegations` |
| `accept_event_delegation(id)` | `accept_event_delegation` |
| `discard_event_delegation(id)` | `discard_event_delegation` |
| `delegate_event(event, org, distribution, message)` | `delegate_event` |

### 5.28 Statistics & Utilities

| Method | PyMISP equivalent |
|--------|-------------------|
| `attributes_statistics(context, percentage)` | `attributes_statistics` |
| `tags_statistics(percentage, name_sort)` | `tags_statistics` |
| `users_statistics(context)` | `users_statistics` |
| `direct_call(url, data, params)` | `direct_call` |
| `freetext(event_id, string, adhere_warninglists, distribution, sharing_group, pythonify)` | `freetext` |
| `upload_stix(path, data, version)` | `upload_stix` |
| `push_event_to_zmq(id)` | `push_event_to_ZMQ` |
| `change_sharing_group_on_entity(entity, sharing_group_id)` | `change_sharing_group_on_entity` |
| `get_all_functions(not_implemented)` | `get_all_functions` |

### 5.29 Standalone Functions

| Function | PyMISP equivalent |
|----------|-------------------|
| `register_user(url, email, org, message, ...)` | `register_user` |

---

## 6. Crate Dependencies

```toml
[dependencies]
reqwest = { version = "0.12", features = ["json", "rustls-tls", "cookies", "brotli"] }
tokio = { version = "1", features = ["full"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
uuid = { version = "1", features = ["v4", "serde"] }
chrono = { version = "0.4", features = ["serde"] }
thiserror = "2"
url = "2"
log = "0.4"
base64 = "0.22"

[dev-dependencies]
tokio-test = "0.4"
wiremock = "0.6"        # HTTP mocking for unit tests
pretty_assertions = "1"

[features]
default = ["async"]
async = []
blocking = ["reqwest/blocking"]
tools-csv = ["csv"]
tools-openioc = ["quick-xml"]
tools-file = ["sha2", "md-5"]
```

---

## 7. Error Handling

```rust
#[derive(Debug, thiserror::Error)]
pub enum MispError {
    #[error("No URL configured")]
    NoUrl,
    #[error("No API key configured")]
    NoKey,
    #[error("HTTP request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("MISP server error: {message}")]
    ServerError { status: u16, message: String },
    #[error("Invalid MISP object: {0}")]
    InvalidObject(String),
    #[error("Unknown object template: {0}")]
    UnknownObjectTemplate(String),
    #[error("Invalid format: {0}")]
    InvalidFormat(String),
    #[error("Unexpected response: {0}")]
    UnexpectedResponse(String),
    #[error("Empty response")]
    EmptyResponse,
    #[error("New event error: {0}")]
    NewEvent(String),
    #[error("New attribute error: {0}")]
    NewAttribute(String),
    #[error("Missing dependency: {0}")]
    MissingDependency(String),
    #[error("Not implemented: {0}")]
    NotImplemented(String),
}

pub type MispResult<T> = Result<T, MispError>;
```

---

## 8. Testing Strategy

### 8.1 Rust Unit Tests (`tests/unit/`)
- Model serialization/deserialization round-trips
- Search parameter building
- Attribute type/category validation against `describeTypes.json`
- Error type coverage

### 8.2 Rust Integration Tests (`tests/integration/`)
- Full CRUD cycles against a live MISP instance
- Environment variables: `MISP_URL`, `MISP_KEY`
- Mirrors the structure of `testlive_comprehensive.py`

### 8.3 Python Test Suite (`tests/python/`)
Copied verbatim from the [PyMISP repository](https://github.com/MISP/PyMISP) (`tests/` directory):
- `test_mispevent.py` — Core data model tests
- `test_analyst_data.py` — Notes/opinions/relationships
- `test_fileobject.py` — File object handling
- `test_emailobject.py` — Email parsing
- `test_attributevalidationtool.py` — Validation logic
- `test_reportlab.py` — PDF export
- `testlive_comprehensive.py` — Full API integration (195KB)
- `testlive_local.py` — Local instance integration (73KB)
- `testlive_sync.py` — Server synchronization tests

These remain Python tests and test PyMISP. They serve as the **reference behavior specification** — RustMISP's Rust integration tests must produce equivalent results for the same operations.

All associated test data files (JSON, CSV, email samples, STIX files) are also copied.

---

## 9. Tools (Feature-Gated)

Optional tool modules behind cargo features, matching PyMISP's `tools/`:

| Feature | Tool | PyMISP equivalent |
|---------|------|-------------------|
| `tools-file` | `FileObject` — generate file objects with hashes | `FileObject` |
| `tools-csv` | `CsvLoader` — CSV to MISP attributes | `CSVLoader` |
| `tools-openioc` | `load_openioc` / `load_openioc_file` | `openioc` |
| `tools-feed` | `FeedGenerator` — generate MISP feeds | `feed_meta_generator` |
| (default) | `GenericObjectGenerator` — build arbitrary objects | `GenericObjectGenerator` |
| (default) | `AbstractMispObjectGenerator` — base for custom objects | `AbstractMISPObjectGenerator` |

> **Note:** Binary analysis tools (PE/ELF/Mach-O), email parsing, URL parsing, and VirusTotal integration are deferred to future iterations as they require significant Rust ecosystem evaluation for equivalent libraries (e.g., `goblin` for PE/ELF, `mail-parser` for email).

---

## 10. Examples

Provide idiomatic Rust examples matching PyMISP's `examples/` directory:

1. **`basic_event.rs`** — Create event, add attributes, publish
2. **`search_attributes.rs`** — Complex search with AND/OR/NOT
3. **`manage_tags.rs`** — Tag CRUD and tagging entities
4. **`feed_operations.rs`** — Feed management lifecycle
5. **`user_management.rs`** — User CRUD operations
6. **`galaxy_operations.rs`** — Galaxy and cluster operations
7. **`sightings.rs`** — Add and query sightings
8. **`sharing_groups.rs`** — Sharing group management

---

## 11. Implementation Phases

### Phase 0: Repository Setup (Iteration 0)
- Create standalone GitHub repository (`github.com/MISP/RustMISP`)
- Initialize with `.gitignore`, `LICENSE` (AGPL-3.0), `README.md`, `CHANGELOG.md`
- Set up GitHub Actions CI (fmt, clippy, test, doc)
- Set up release workflow for crates.io publishing
- Remove `RustMISP/` from MISP working tree and add as git submodule
- Verify independent clone and MISP `--recurse-submodules` both work

### Phase 1: Foundation (Iterations 1–3)
- Project scaffolding, Cargo.toml
- Core enums (`Distribution`, `ThreatLevel`, `Analysis`)
- Error types
- Base `MispClient` with authentication, TLS, proxy config
- HTTP layer (`_prepare_request`, `_check_response`)
- `MispEvent`, `MispAttribute`, `MispTag` models
- Event CRUD + publish/unpublish
- Attribute CRUD + restore
- Tag CRUD + tag/untag entities
- Unit tests for all models (serde round-trips)

### Phase 2: Object Model & Proposals (Iterations 4–5)
- `MispObject`, `MispObjectReference`, `MispObjectAttribute`, `MispObjectTemplate`
- Object CRUD + references
- Object template operations
- `MispShadowAttribute` — proposal workflow (add/update/delete/accept/discard)
- Sightings (add/delete/query)
- `MispEventReport` CRUD

### Phase 3: Intelligence Layer (Iterations 6–7)
- `MispTaxonomy` — CRUD + enable/disable + tags
- `MispWarninglist` — CRUD + toggle + value check
- `MispNoticelist` — CRUD + enable/disable
- `MispGalaxy`, `MispGalaxyCluster`, `MispGalaxyClusterElement`, `MispGalaxyClusterRelation`
- Galaxy CRUD + cluster operations + attach to entities
- `MispDecayingModel` — CRUD + enable/disable
- `MispCorrelationExclusion` — CRUD + clean

### Phase 4: Administration (Iterations 8–9)
- `MispOrganisation` — CRUD
- `MispUser`, `MispRole` — CRUD + password + authkey + registration workflow
- `MispServer` — CRUD + pull/push/test
- `MispFeed` — full lifecycle (CRUD + enable/disable + cache + fetch + compare)
- `MispSharingGroup` — CRUD + org/server membership
- `MispUserSetting` — CRUD

### Phase 5: Search & Advanced (Iterations 10–11)
- `search()` with full 50+ parameter support
- `SearchBuilder` for ergonomic query construction
- `search_index()`, `search_sightings()`, `search_logs()`, `search_feeds()`
- `build_complex_query()` (AND/OR/NOT)
- `freetext()` parsing
- `upload_stix()` (v1 and v2)
- `direct_call()` for raw API access
- Statistics endpoints
- Blocklists (event + organisation)
- Communities + event delegations
- ZMQ push

### Phase 6: Tools & Polish (Iterations 12–14)
- `GenericObjectGenerator` and `AbstractMispObjectGenerator`
- Feature-gated tools: FileObject, CsvLoader, OpenIOC, FeedGenerator
- Attribute type/category validation from `describeTypes.json`
- Blocking client wrapper
- Copy Python test suite from PyMISP repo into `tests/python/`
- Rust integration tests mirroring `testlive_comprehensive.py`
- Examples
- Documentation (rustdoc)
- README.md

---

## 12. Non-Goals (Explicitly Out of Scope)

- **GUI or CLI tool** — RustMISP is a library only
- **Database access** — API-only, no direct MySQL/Redis
- **Full STIX conversion** — `upload_stix` sends raw data to MISP's built-in converter
- **Async Python bindings** — No PyO3/pyo3-asyncio bridge
- **Binary analysis tools** (PE/ELF/Mach-O) — Deferred; requires ecosystem evaluation
- **Email parsing tools** — Deferred; requires `mail-parser` evaluation
- **PDF report generation** — Deferred; no Rust reportlab equivalent
- **VirusTotal integration** — Deferred; API-specific tool
- **Neo4j export** — Deferred; niche use case

---

## 13. Success Criteria

1. All 243 PyMISP API methods have Rust equivalents
2. All 30+ data models serialize/deserialize correctly with MISP's JSON format
3. Rust unit tests pass for model round-trips and validation
4. Rust integration tests pass against a live MISP 2.5 instance
5. Python test suite (`testlive_comprehensive.py`) passes against the same instance, confirming behavioral equivalence
6. `cargo doc` generates complete API documentation
7. Compiles on stable Rust with no `unsafe` code
