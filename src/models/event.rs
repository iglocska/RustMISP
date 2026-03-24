use serde::{Deserialize, Serialize};

use super::attribute::MispAttribute;
use super::serde_helpers::{flexible_bool, string_or_i64_opt};
use super::tag::MispTag;

/// A MISP event — the primary container for threat intelligence data.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MispEvent {
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

    /// Event title / description. Required on creation.
    #[serde(default)]
    pub info: String,

    /// Event date in `YYYY-MM-DD` format.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub date: Option<String>,

    /// Threat level: 1=High, 2=Medium, 3=Low, 4=Undefined.
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub threat_level_id: Option<i64>,

    /// Analysis state: 0=Initial, 1=Ongoing, 2=Complete.
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub analysis: Option<i64>,

    /// Distribution level: 0-5.
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub distribution: Option<i64>,

    /// Whether the event is published.
    #[serde(default, with = "flexible_bool")]
    pub published: bool,

    /// Sharing group ID (when distribution == 4).
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub sharing_group_id: Option<i64>,

    /// Organisation ID that owns this event.
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub org_id: Option<i64>,

    /// Organisation ID that created this event.
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub orgc_id: Option<i64>,

    /// Number of attributes in this event.
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub attribute_count: Option<i64>,

    /// Unix timestamp of last modification.
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub timestamp: Option<i64>,

    /// Unix timestamp of publication.
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub publish_timestamp: Option<i64>,

    /// Whether the event is locked.
    #[serde(default, with = "flexible_bool")]
    pub locked: bool,

    /// Whether proposal email notifications are locked.
    #[serde(default, with = "flexible_bool")]
    pub proposal_email_lock: bool,

    /// Whether correlation is disabled for this event.
    #[serde(default, with = "flexible_bool")]
    pub disable_correlation: bool,

    /// UUID of a parent event this event extends.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extends_uuid: Option<String>,

    /// Whether the event is cryptographically protected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protected: Option<bool>,

    /// Email of the event creator.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_creator_email: Option<String>,

    /// Owner organisation (embedded).
    #[serde(default, rename = "Org", skip_serializing_if = "Option::is_none")]
    pub org: Option<MispEventOrg>,

    /// Creator organisation (embedded).
    #[serde(default, rename = "Orgc", skip_serializing_if = "Option::is_none")]
    pub orgc: Option<MispEventOrg>,

    /// Attributes in this event.
    #[serde(default, rename = "Attribute", skip_serializing_if = "Vec::is_empty")]
    pub attributes: Vec<MispAttribute>,

    /// Tags applied to this event.
    #[serde(default, rename = "Tag", skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<MispTag>,
}

/// Minimal organisation reference embedded in event responses.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MispEventOrg {
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub id: Option<i64>,
    #[serde(default)]
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
}

impl MispEvent {
    /// Create a new event with required `info` field.
    pub fn new(info: impl Into<String>) -> Self {
        Self {
            id: None,
            uuid: None,
            info: info.into(),
            date: None,
            threat_level_id: None,
            analysis: None,
            distribution: None,
            published: false,
            sharing_group_id: None,
            org_id: None,
            orgc_id: None,
            attribute_count: None,
            timestamp: None,
            publish_timestamp: None,
            locked: false,
            proposal_email_lock: false,
            disable_correlation: false,
            extends_uuid: None,
            protected: None,
            event_creator_email: None,
            org: None,
            orgc: None,
            attributes: Vec::new(),
            tags: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_new_defaults() {
        let event = MispEvent::new("Test event");
        assert_eq!(event.info, "Test event");
        assert!(!event.published);
        assert!(event.id.is_none());
        assert!(event.attributes.is_empty());
        assert!(event.tags.is_empty());
    }

    #[test]
    fn event_serde_roundtrip() {
        let event = MispEvent {
            id: Some(1),
            uuid: Some("54884656-2da8-4625-bf07-43ef950d210b".into()),
            info: "OSINT - F-Secure W32/Regin".into(),
            date: Some("2014-12-10".into()),
            threat_level_id: Some(1),
            analysis: Some(2),
            distribution: Some(1),
            published: true,
            sharing_group_id: None,
            org_id: Some(1),
            orgc_id: Some(2),
            attribute_count: Some(39),
            timestamp: Some(1418204882),
            publish_timestamp: Some(1418204883),
            locked: false,
            proposal_email_lock: false,
            disable_correlation: false,
            extends_uuid: None,
            protected: None,
            event_creator_email: None,
            org: Some(MispEventOrg {
                id: Some(1),
                name: "ORGNAME".into(),
                uuid: None,
            }),
            orgc: Some(MispEventOrg {
                id: Some(2),
                name: "CIRCL".into(),
                uuid: None,
            }),
            attributes: vec![MispAttribute::new("md5", "Payload delivery", "abc123")],
            tags: vec![MispTag::new("osint")],
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: MispEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }

    #[test]
    fn event_deserialize_misp_format() {
        let json = r#"{
            "id": "1",
            "uuid": "54884656-2da8-4625-bf07-43ef950d210b",
            "org_id": "1",
            "orgc_id": "2",
            "date": "2014-12-10",
            "info": "OSINT - F-Secure W32/Regin, Stage #1",
            "published": true,
            "analysis": "2",
            "attribute_count": "39",
            "threat_level_id": "1",
            "distribution": "1",
            "timestamp": "1418204882",
            "publish_timestamp": "1418204883",
            "locked": 0,
            "proposal_email_lock": 0,
            "disable_correlation": false,
            "Org": {"id": "1", "name": "ORGNAME"},
            "Orgc": {"id": "2", "name": "CIRCL"},
            "Attribute": [
                {
                    "id": "39",
                    "type": "md5",
                    "category": "Payload delivery",
                    "value": "049436bb90f71cf38549817d9b90e2da",
                    "comment": "",
                    "to_ids": true,
                    "distribution": "0",
                    "timestamp": "1418204882",
                    "deleted": false,
                    "disable_correlation": false
                }
            ],
            "Tag": [
                {"name": "osint"},
                {"name": "tlp:green"}
            ]
        }"#;
        let event: MispEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.id, Some(1));
        assert_eq!(event.info, "OSINT - F-Secure W32/Regin, Stage #1");
        assert!(event.published);
        assert_eq!(event.analysis, Some(2));
        assert_eq!(event.attributes.len(), 1);
        assert_eq!(event.attributes[0].attr_type, "md5");
        assert_eq!(event.tags.len(), 2);
        assert_eq!(event.tags[0].name, "osint");
        assert_eq!(event.org.as_ref().unwrap().name, "ORGNAME");
        assert_eq!(event.orgc.as_ref().unwrap().name, "CIRCL");
    }

    #[test]
    fn event_wrapped_response() {
        // MISP wraps single event responses in {"Event": {...}}
        let json = r#"{"Event": {"id": "5", "info": "Test", "published": false}}"#;
        let val: serde_json::Value = serde_json::from_str(json).unwrap();
        let event: MispEvent = serde_json::from_value(val["Event"].clone()).unwrap();
        assert_eq!(event.id, Some(5));
        assert_eq!(event.info, "Test");
    }
}
