use serde::{Deserialize, Serialize};

use super::serde_helpers::{flexible_bool, string_or_i64_opt};
use super::tag::MispTag;

/// A MISP galaxy cluster element — a key-value pair within a galaxy cluster.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MispGalaxyClusterElement {
    /// Unique numeric identifier (set by server).
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub id: Option<i64>,

    /// ID of the parent galaxy cluster.
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub galaxy_cluster_id: Option<i64>,

    /// Element key.
    #[serde(default)]
    pub key: String,

    /// Element value.
    #[serde(default)]
    pub value: String,
}

impl MispGalaxyClusterElement {
    /// Create a new galaxy cluster element with a key and value.
    pub fn new(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            id: None,
            galaxy_cluster_id: None,
            key: key.into(),
            value: value.into(),
        }
    }
}

impl Default for MispGalaxyClusterElement {
    fn default() -> Self {
        Self::new("", "")
    }
}

/// A MISP galaxy cluster relation — a link between two galaxy clusters.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct MispGalaxyClusterRelation {
    /// Unique numeric identifier (set by server).
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub id: Option<i64>,

    /// ID of the source galaxy cluster.
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub galaxy_cluster_id: Option<i64>,

    /// ID of the referenced (target) galaxy cluster.
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub referenced_galaxy_cluster_id: Option<i64>,

    /// UUID of the referenced galaxy cluster.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub referenced_galaxy_cluster_uuid: Option<String>,

    /// Distribution level of the relation.
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub distribution: Option<i64>,

    /// Type of relationship (e.g., "related-to", "similar-to").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relationship_type: Option<String>,

    /// Tags attached to this relation.
    #[serde(default, rename = "Tag", skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<MispTag>,
}

impl MispGalaxyClusterRelation {
    /// Create a new galaxy cluster relation.
    pub fn new(referenced_uuid: impl Into<String>, relationship_type: impl Into<String>) -> Self {
        Self {
            id: None,
            galaxy_cluster_id: None,
            referenced_galaxy_cluster_id: None,
            referenced_galaxy_cluster_uuid: Some(referenced_uuid.into()),
            distribution: None,
            relationship_type: Some(relationship_type.into()),
            tags: Vec::new(),
        }
    }
}

/// A MISP galaxy cluster — an individual threat actor, malware, tool, or
/// other intelligence item within a galaxy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MispGalaxyCluster {
    /// Unique numeric identifier (set by server).
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub id: Option<i64>,

    /// UUID of the cluster.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,

    /// Type of the cluster (matches the galaxy type).
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub cluster_type: Option<String>,

    /// Human-readable value (e.g., "APT28", "Emotet").
    #[serde(default)]
    pub value: String,

    /// Tag name derived from the cluster (e.g., "misp-galaxy:threat-actor=\"APT28\"").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag_name: Option<String>,

    /// Description of the cluster.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Source of the cluster data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,

    /// Authors of the cluster.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authors: Option<Vec<String>>,

    /// Version of the cluster.
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub version: Option<i64>,

    /// Distribution level.
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub distribution: Option<i64>,

    /// Organisation ID of the cluster creator.
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub org_id: Option<i64>,

    /// Organisation ID of the original creator.
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub orgc_id: Option<i64>,

    /// Whether this cluster is the default (upstream) version.
    #[serde(default, with = "flexible_bool")]
    pub default: bool,

    /// Whether this cluster has been published.
    #[serde(default, with = "flexible_bool")]
    pub published: bool,

    /// Galaxy cluster elements (key-value metadata).
    #[serde(
        default,
        rename = "GalaxyClusterElement",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub galaxy_cluster_elements: Vec<MispGalaxyClusterElement>,

    /// Galaxy cluster relations (links to other clusters).
    #[serde(
        default,
        rename = "GalaxyClusterRelation",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub galaxy_cluster_relations: Vec<MispGalaxyClusterRelation>,
}

impl MispGalaxyCluster {
    /// Create a new galaxy cluster with a value.
    pub fn new(value: impl Into<String>) -> Self {
        Self {
            id: None,
            uuid: None,
            cluster_type: None,
            value: value.into(),
            tag_name: None,
            description: None,
            source: None,
            authors: None,
            version: None,
            distribution: None,
            org_id: None,
            orgc_id: None,
            default: false,
            published: false,
            galaxy_cluster_elements: Vec::new(),
            galaxy_cluster_relations: Vec::new(),
        }
    }
}

impl Default for MispGalaxyCluster {
    fn default() -> Self {
        Self::new("")
    }
}

/// A MISP galaxy — a classification framework grouping related clusters
/// (e.g., "threat-actor", "mitre-attack-pattern", "tool").
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MispGalaxy {
    /// Unique numeric identifier (set by server).
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub id: Option<i64>,

    /// UUID of the galaxy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,

    /// Human-readable name (e.g., "Threat Actor", "MITRE ATT&CK").
    #[serde(default)]
    pub name: String,

    /// Machine-readable type (e.g., "threat-actor", "mitre-attack-pattern").
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub galaxy_type: Option<String>,

    /// Description of the galaxy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Version of the galaxy definition.
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub version: Option<i64>,

    /// Namespace of the galaxy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,

    /// Whether the galaxy is enabled.
    #[serde(default, with = "flexible_bool")]
    pub enabled: bool,

    /// Whether the galaxy is local-only.
    #[serde(default, with = "flexible_bool")]
    pub local_only: bool,

    /// Galaxy clusters contained in this galaxy.
    #[serde(
        default,
        rename = "GalaxyCluster",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub galaxy_clusters: Vec<MispGalaxyCluster>,
}

impl MispGalaxy {
    /// Create a new galaxy with a name.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            id: None,
            uuid: None,
            name: name.into(),
            galaxy_type: None,
            description: None,
            version: None,
            namespace: None,
            enabled: false,
            local_only: false,
            galaxy_clusters: Vec::new(),
        }
    }
}

impl Default for MispGalaxy {
    fn default() -> Self {
        Self::new("")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── MispGalaxyClusterElement tests ──────────────────────────────

    #[test]
    fn element_new_defaults() {
        let e = MispGalaxyClusterElement::new("country", "US");
        assert_eq!(e.key, "country");
        assert_eq!(e.value, "US");
        assert!(e.id.is_none());
        assert!(e.galaxy_cluster_id.is_none());
    }

    #[test]
    fn element_serde_roundtrip() {
        let e = MispGalaxyClusterElement {
            id: Some(1),
            galaxy_cluster_id: Some(10),
            key: "country".into(),
            value: "US".into(),
        };
        let json = serde_json::to_string(&e).unwrap();
        let back: MispGalaxyClusterElement = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
    }

    #[test]
    fn element_deserialize_misp_format() {
        let json = r#"{
            "id": "1",
            "galaxy_cluster_id": "10",
            "key": "country",
            "value": "US"
        }"#;
        let e: MispGalaxyClusterElement = serde_json::from_str(json).unwrap();
        assert_eq!(e.id, Some(1));
        assert_eq!(e.galaxy_cluster_id, Some(10));
        assert_eq!(e.key, "country");
        assert_eq!(e.value, "US");
    }

    // ── MispGalaxyClusterRelation tests ─────────────────────────────

    #[test]
    fn relation_new_defaults() {
        let r = MispGalaxyClusterRelation::new("target-uuid", "related-to");
        assert_eq!(
            r.referenced_galaxy_cluster_uuid.as_deref(),
            Some("target-uuid")
        );
        assert_eq!(r.relationship_type.as_deref(), Some("related-to"));
        assert!(r.id.is_none());
        assert!(r.tags.is_empty());
    }

    #[test]
    fn relation_serde_roundtrip() {
        let r = MispGalaxyClusterRelation {
            id: Some(5),
            galaxy_cluster_id: Some(10),
            referenced_galaxy_cluster_id: Some(20),
            referenced_galaxy_cluster_uuid: Some("uuid-20".into()),
            distribution: Some(0),
            relationship_type: Some("related-to".into()),
            tags: vec![MispTag::new("tlp:white")],
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: MispGalaxyClusterRelation = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn relation_deserialize_misp_format() {
        let json = r#"{
            "id": "5",
            "galaxy_cluster_id": "10",
            "referenced_galaxy_cluster_id": "20",
            "referenced_galaxy_cluster_uuid": "uuid-20",
            "distribution": "0",
            "relationship_type": "related-to"
        }"#;
        let r: MispGalaxyClusterRelation = serde_json::from_str(json).unwrap();
        assert_eq!(r.id, Some(5));
        assert_eq!(r.referenced_galaxy_cluster_id, Some(20));
        assert_eq!(r.relationship_type.as_deref(), Some("related-to"));
    }

    // ── MispGalaxyCluster tests ─────────────────────────────────────

    #[test]
    fn cluster_new_defaults() {
        let c = MispGalaxyCluster::new("APT28");
        assert_eq!(c.value, "APT28");
        assert!(c.id.is_none());
        assert!(!c.default);
        assert!(!c.published);
        assert!(c.galaxy_cluster_elements.is_empty());
        assert!(c.galaxy_cluster_relations.is_empty());
    }

    #[test]
    fn cluster_serde_roundtrip() {
        let c = MispGalaxyCluster {
            id: Some(42),
            uuid: Some("cluster-uuid".into()),
            cluster_type: Some("threat-actor".into()),
            value: "APT28".into(),
            tag_name: Some("misp-galaxy:threat-actor=\"APT28\"".into()),
            description: Some("Russian threat actor".into()),
            source: Some("MISP".into()),
            authors: Some(vec!["MISP Project".into()]),
            version: Some(3),
            distribution: Some(0),
            org_id: Some(1),
            orgc_id: Some(1),
            default: true,
            published: true,
            galaxy_cluster_elements: vec![MispGalaxyClusterElement::new("country", "RU")],
            galaxy_cluster_relations: Vec::new(),
        };
        let json = serde_json::to_string(&c).unwrap();
        let back: MispGalaxyCluster = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn cluster_deserialize_misp_format() {
        let json = r#"{
            "id": "42",
            "uuid": "cluster-uuid",
            "type": "threat-actor",
            "value": "APT28",
            "tag_name": "misp-galaxy:threat-actor=\"APT28\"",
            "description": "Russian threat actor",
            "source": "MISP",
            "authors": ["MISP Project"],
            "version": "3",
            "distribution": "0",
            "org_id": "1",
            "orgc_id": "1",
            "default": "1",
            "published": true
        }"#;
        let c: MispGalaxyCluster = serde_json::from_str(json).unwrap();
        assert_eq!(c.id, Some(42));
        assert_eq!(c.cluster_type.as_deref(), Some("threat-actor"));
        assert_eq!(c.value, "APT28");
        assert!(c.default);
        assert!(c.published);
        assert_eq!(c.version, Some(3));
    }

    #[test]
    fn cluster_type_field_rename() {
        let c = MispGalaxyCluster {
            cluster_type: Some("threat-actor".into()),
            ..MispGalaxyCluster::new("test")
        };
        let json = serde_json::to_string(&c).unwrap();
        let val: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(val["type"], "threat-actor");
        assert!(val.get("cluster_type").is_none());
    }

    #[test]
    fn cluster_with_nested_elements_and_relations() {
        let json = r#"{
            "id": "42",
            "value": "APT28",
            "default": false,
            "published": false,
            "GalaxyClusterElement": [
                {"id": "1", "galaxy_cluster_id": "42", "key": "country", "value": "RU"},
                {"id": "2", "galaxy_cluster_id": "42", "key": "cfr-type-of-incident", "value": "Espionage"}
            ],
            "GalaxyClusterRelation": [
                {
                    "id": "10",
                    "galaxy_cluster_id": "42",
                    "referenced_galaxy_cluster_id": "50",
                    "referenced_galaxy_cluster_uuid": "uuid-50",
                    "relationship_type": "uses"
                }
            ]
        }"#;
        let c: MispGalaxyCluster = serde_json::from_str(json).unwrap();
        assert_eq!(c.galaxy_cluster_elements.len(), 2);
        assert_eq!(c.galaxy_cluster_elements[0].key, "country");
        assert_eq!(c.galaxy_cluster_elements[1].key, "cfr-type-of-incident");
        assert_eq!(c.galaxy_cluster_relations.len(), 1);
        assert_eq!(
            c.galaxy_cluster_relations[0].relationship_type.as_deref(),
            Some("uses")
        );
    }

    // ── MispGalaxy tests ────────────────────────────────────────────

    #[test]
    fn galaxy_new_defaults() {
        let g = MispGalaxy::new("Threat Actor");
        assert_eq!(g.name, "Threat Actor");
        assert!(g.id.is_none());
        assert!(!g.enabled);
        assert!(!g.local_only);
        assert!(g.galaxy_clusters.is_empty());
    }

    #[test]
    fn galaxy_serde_roundtrip() {
        let g = MispGalaxy {
            id: Some(1),
            uuid: Some("galaxy-uuid".into()),
            name: "Threat Actor".into(),
            galaxy_type: Some("threat-actor".into()),
            description: Some("Known threat actors".into()),
            version: Some(5),
            namespace: Some("misp".into()),
            enabled: true,
            local_only: false,
            galaxy_clusters: Vec::new(),
        };
        let json = serde_json::to_string(&g).unwrap();
        let back: MispGalaxy = serde_json::from_str(&json).unwrap();
        assert_eq!(g, back);
    }

    #[test]
    fn galaxy_deserialize_misp_format() {
        let json = r#"{
            "id": "1",
            "uuid": "galaxy-uuid",
            "name": "Threat Actor",
            "type": "threat-actor",
            "description": "Known threat actors",
            "version": "5",
            "namespace": "misp",
            "enabled": "1",
            "local_only": "0"
        }"#;
        let g: MispGalaxy = serde_json::from_str(json).unwrap();
        assert_eq!(g.id, Some(1));
        assert_eq!(g.name, "Threat Actor");
        assert_eq!(g.galaxy_type.as_deref(), Some("threat-actor"));
        assert!(g.enabled);
        assert!(!g.local_only);
    }

    #[test]
    fn galaxy_type_field_rename() {
        let g = MispGalaxy {
            galaxy_type: Some("threat-actor".into()),
            ..MispGalaxy::new("test")
        };
        let json = serde_json::to_string(&g).unwrap();
        let val: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(val["type"], "threat-actor");
        assert!(val.get("galaxy_type").is_none());
    }

    #[test]
    fn galaxy_with_nested_clusters() {
        let json = r#"{
            "id": "1",
            "name": "Threat Actor",
            "type": "threat-actor",
            "enabled": true,
            "local_only": false,
            "GalaxyCluster": [
                {
                    "id": "42",
                    "value": "APT28",
                    "type": "threat-actor",
                    "default": true,
                    "published": true
                },
                {
                    "id": "43",
                    "value": "APT29",
                    "type": "threat-actor",
                    "default": true,
                    "published": true
                }
            ]
        }"#;
        let g: MispGalaxy = serde_json::from_str(json).unwrap();
        assert_eq!(g.galaxy_clusters.len(), 2);
        assert_eq!(g.galaxy_clusters[0].value, "APT28");
        assert_eq!(g.galaxy_clusters[1].value, "APT29");
    }
}
