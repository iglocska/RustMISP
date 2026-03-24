use serde::{Deserialize, Serialize};

use super::serde_helpers::{flexible_bool, string_or_i64_opt};

/// A MISP shadow attribute (attribute proposal).
///
/// Shadow attributes represent proposed changes to attributes. They can be
/// proposals to add new attributes, modify existing ones, or delete them.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MispShadowAttribute {
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

    /// The ID of the original attribute being proposed for modification.
    /// `0` or `None` for proposals to add a new attribute.
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub old_id: Option<i64>,

    /// Organisation ID of the proposer.
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub org_id: Option<i64>,

    /// Event organisation ID.
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub event_org_id: Option<i64>,

    /// Event UUID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_uuid: Option<String>,

    /// Attribute type (e.g., `"ip-dst"`, `"md5"`, `"domain"`).
    #[serde(rename = "type")]
    pub attr_type: String,

    /// Attribute category (e.g., `"Network activity"`, `"Payload delivery"`).
    pub category: String,

    /// The proposed indicator value.
    pub value: String,

    /// Comment/context for this proposal.
    #[serde(default)]
    pub comment: String,

    /// Whether this attribute should be used for IDS detection.
    #[serde(default, with = "flexible_bool")]
    pub to_ids: bool,

    /// Whether this is a proposal to delete the attribute.
    #[serde(default, with = "flexible_bool")]
    pub proposal_to_delete: bool,

    /// Soft-deletion flag.
    #[serde(default, with = "flexible_bool")]
    pub deleted: bool,

    /// Unix timestamp of last modification.
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub timestamp: Option<i64>,

    /// First observation datetime.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_seen: Option<String>,

    /// Last observation datetime.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<String>,

    /// Whether correlation is disabled for this attribute.
    #[serde(default, with = "flexible_bool")]
    pub disable_correlation: bool,
}

impl MispShadowAttribute {
    /// Create a new shadow attribute proposal with required fields.
    pub fn new(
        attr_type: impl Into<String>,
        category: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        Self {
            id: None,
            uuid: None,
            event_id: None,
            old_id: None,
            org_id: None,
            event_org_id: None,
            event_uuid: None,
            attr_type: attr_type.into(),
            category: category.into(),
            value: value.into(),
            comment: String::new(),
            to_ids: false,
            proposal_to_delete: false,
            deleted: false,
            timestamp: None,
            first_seen: None,
            last_seen: None,
            disable_correlation: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shadow_attribute_new_defaults() {
        let sa = MispShadowAttribute::new("ip-dst", "Network activity", "1.2.3.4");
        assert_eq!(sa.attr_type, "ip-dst");
        assert_eq!(sa.category, "Network activity");
        assert_eq!(sa.value, "1.2.3.4");
        assert!(!sa.to_ids);
        assert!(!sa.proposal_to_delete);
        assert!(sa.id.is_none());
        assert!(sa.old_id.is_none());
    }

    #[test]
    fn shadow_attribute_serde_roundtrip() {
        let sa = MispShadowAttribute {
            id: Some(5),
            uuid: Some("aaaa-bbbb-cccc".into()),
            event_id: Some(1),
            old_id: Some(39),
            org_id: Some(2),
            event_org_id: Some(1),
            event_uuid: None,
            attr_type: "md5".into(),
            category: "Payload delivery".into(),
            value: "049436bb90f71cf38549817d9b90e2da".into(),
            comment: "Proposed change".into(),
            to_ids: true,
            proposal_to_delete: false,
            deleted: false,
            timestamp: Some(1418204882),
            first_seen: None,
            last_seen: None,
            disable_correlation: false,
        };
        let json = serde_json::to_string(&sa).unwrap();
        let back: MispShadowAttribute = serde_json::from_str(&json).unwrap();
        assert_eq!(sa, back);
    }

    #[test]
    fn shadow_attribute_deserialize_misp_format() {
        let json = r#"{
            "id": "5",
            "uuid": "aaaa-bbbb-cccc",
            "event_id": "1",
            "old_id": "39",
            "org_id": "2",
            "event_org_id": "1",
            "type": "md5",
            "category": "Payload delivery",
            "value": "049436bb90f71cf38549817d9b90e2da",
            "comment": "",
            "to_ids": "1",
            "proposal_to_delete": false,
            "deleted": false,
            "timestamp": "1418204882",
            "disable_correlation": "0"
        }"#;
        let sa: MispShadowAttribute = serde_json::from_str(json).unwrap();
        assert_eq!(sa.id, Some(5));
        assert_eq!(sa.old_id, Some(39));
        assert_eq!(sa.attr_type, "md5");
        assert!(sa.to_ids);
        assert!(!sa.proposal_to_delete);
    }

    #[test]
    fn shadow_attribute_proposal_to_delete() {
        let json = r#"{
            "id": "10",
            "event_id": "1",
            "old_id": "39",
            "type": "md5",
            "category": "Payload delivery",
            "value": "049436bb90f71cf38549817d9b90e2da",
            "comment": "Delete this",
            "to_ids": true,
            "proposal_to_delete": true,
            "deleted": false,
            "disable_correlation": false
        }"#;
        let sa: MispShadowAttribute = serde_json::from_str(json).unwrap();
        assert!(sa.proposal_to_delete);
        assert_eq!(sa.comment, "Delete this");
    }
}
