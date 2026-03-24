use serde::{Deserialize, Serialize};

use super::serde_helpers::{flexible_bool, string_or_i64_opt};
use super::tag::MispTag;

/// A MISP attribute — an individual indicator of compromise (IoC).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MispAttribute {
    /// Unique numeric identifier (set by server).
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub id: Option<i64>,

    /// UUID (set by server or provided on creation).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,

    /// Parent event ID.
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub event_id: Option<i64>,

    /// Parent object ID (`0` if standalone).
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub object_id: Option<i64>,

    /// Relationship name when part of a MISP object.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_relation: Option<String>,

    /// Attribute type (e.g., `"ip-dst"`, `"md5"`, `"domain"`).
    #[serde(rename = "type")]
    pub attr_type: String,

    /// Attribute category (e.g., `"Network activity"`, `"Payload delivery"`).
    pub category: String,

    /// The indicator value.
    pub value: String,

    /// Comment/context for this attribute.
    #[serde(default)]
    pub comment: String,

    /// Whether this attribute should be used for IDS detection.
    #[serde(default, with = "flexible_bool")]
    pub to_ids: bool,

    /// Distribution level.
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub distribution: Option<i64>,

    /// Sharing group ID (when distribution == 4).
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub sharing_group_id: Option<i64>,

    /// Unix timestamp of last modification.
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub timestamp: Option<i64>,

    /// Soft-deletion flag.
    #[serde(default, with = "flexible_bool")]
    pub deleted: bool,

    /// Whether correlation is disabled for this attribute.
    #[serde(default, with = "flexible_bool")]
    pub disable_correlation: bool,

    /// First observation datetime.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_seen: Option<String>,

    /// Last observation datetime.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<String>,

    /// Base64-encoded file data (for attachment/malware-sample types).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,

    /// UUID of the parent event.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_uuid: Option<String>,

    /// Tags applied to this attribute.
    #[serde(default, rename = "Tag", skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<MispTag>,
}

impl MispAttribute {
    /// Create a new attribute with required fields.
    pub fn new(
        attr_type: impl Into<String>,
        category: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        Self {
            id: None,
            uuid: None,
            event_id: None,
            object_id: None,
            object_relation: None,
            attr_type: attr_type.into(),
            category: category.into(),
            value: value.into(),
            comment: String::new(),
            to_ids: false,
            distribution: None,
            sharing_group_id: None,
            timestamp: None,
            deleted: false,
            disable_correlation: false,
            first_seen: None,
            last_seen: None,
            data: None,
            event_uuid: None,
            tags: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attribute_new_defaults() {
        let attr = MispAttribute::new("ip-dst", "Network activity", "1.2.3.4");
        assert_eq!(attr.attr_type, "ip-dst");
        assert_eq!(attr.category, "Network activity");
        assert_eq!(attr.value, "1.2.3.4");
        assert!(!attr.to_ids);
        assert!(attr.id.is_none());
    }

    #[test]
    fn attribute_serde_roundtrip() {
        let attr = MispAttribute {
            id: Some(39),
            uuid: Some("56d41e2b-520b-4a74-a12b-cb2a3f8e6b0a".into()),
            event_id: Some(1),
            object_id: Some(0),
            object_relation: None,
            attr_type: "md5".into(),
            category: "Payload delivery".into(),
            value: "049436bb90f71cf38549817d9b90e2da".into(),
            comment: String::new(),
            to_ids: true,
            distribution: Some(0),
            sharing_group_id: Some(0),
            timestamp: Some(1418204882),
            deleted: false,
            disable_correlation: false,
            first_seen: None,
            last_seen: None,
            data: None,
            event_uuid: None,
            tags: vec![MispTag::new("osint")],
        };
        let json = serde_json::to_string(&attr).unwrap();
        let back: MispAttribute = serde_json::from_str(&json).unwrap();
        assert_eq!(attr, back);
    }

    #[test]
    fn attribute_deserialize_misp_format() {
        let json = r#"{
            "id": "39",
            "uuid": "56d41e2b-520b-4a74-a12b-cb2a3f8e6b0a",
            "event_id": "1",
            "object_id": "0",
            "type": "md5",
            "category": "Payload delivery",
            "value": "049436bb90f71cf38549817d9b90e2da",
            "comment": "",
            "to_ids": true,
            "distribution": "0",
            "sharing_group_id": "0",
            "timestamp": "1418204882",
            "deleted": false,
            "disable_correlation": false,
            "first_seen": null,
            "last_seen": null,
            "Tag": [{"name": "osint"}]
        }"#;
        let attr: MispAttribute = serde_json::from_str(json).unwrap();
        assert_eq!(attr.id, Some(39));
        assert_eq!(attr.attr_type, "md5");
        assert_eq!(attr.value, "049436bb90f71cf38549817d9b90e2da");
        assert!(attr.to_ids);
        assert_eq!(attr.tags.len(), 1);
        assert_eq!(attr.tags[0].name, "osint");
    }

    #[test]
    fn attribute_type_field_rename() {
        let attr = MispAttribute::new("domain", "Network activity", "example.com");
        let json = serde_json::to_string(&attr).unwrap();
        let val: serde_json::Value = serde_json::from_str(&json).unwrap();
        // "type" key in JSON, "attr_type" in Rust
        assert_eq!(val["type"], "domain");
        assert!(val.get("attr_type").is_none());
    }
}
