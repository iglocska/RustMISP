use serde::{Deserialize, Serialize};

use super::serde_helpers::string_or_i64_opt;

/// A MISP sighting — records that an indicator was observed.
///
/// Sighting types:
/// - `0` — Sighting (indicator was seen)
/// - `1` — False positive
/// - `2` — Expiration (indicator is no longer relevant)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MispSighting {
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

    /// The attribute ID this sighting is for.
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub attribute_id: Option<i64>,

    /// The event ID this sighting is associated with.
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub event_id: Option<i64>,

    /// Organisation ID of the reporter.
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub org_id: Option<i64>,

    /// Unix timestamp of when the sighting was made.
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub date_sighting: Option<i64>,

    /// Source of the sighting (e.g., a tool or feed name).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,

    /// Sighting type: 0=sighting, 1=false-positive, 2=expiration.
    #[serde(
        default,
        rename = "type",
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub sighting_type: Option<i64>,

    /// The attribute UUID this sighting refers to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute_uuid: Option<String>,
}

impl MispSighting {
    /// Create a new sighting (type 0 = seen).
    pub fn new() -> Self {
        Self {
            id: None,
            uuid: None,
            attribute_id: None,
            event_id: None,
            org_id: None,
            date_sighting: None,
            source: None,
            sighting_type: Some(0),
            attribute_uuid: None,
        }
    }

    /// Create a false-positive sighting (type 1).
    pub fn false_positive() -> Self {
        let mut s = Self::new();
        s.sighting_type = Some(1);
        s
    }

    /// Create an expiration sighting (type 2).
    pub fn expiration() -> Self {
        let mut s = Self::new();
        s.sighting_type = Some(2);
        s
    }
}

impl Default for MispSighting {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sighting_new_defaults() {
        let s = MispSighting::new();
        assert_eq!(s.sighting_type, Some(0));
        assert!(s.id.is_none());
        assert!(s.source.is_none());
    }

    #[test]
    fn sighting_false_positive() {
        let s = MispSighting::false_positive();
        assert_eq!(s.sighting_type, Some(1));
    }

    #[test]
    fn sighting_expiration() {
        let s = MispSighting::expiration();
        assert_eq!(s.sighting_type, Some(2));
    }

    #[test]
    fn sighting_serde_roundtrip() {
        let s = MispSighting {
            id: Some(42),
            uuid: Some("sight-uuid-1234".into()),
            attribute_id: Some(7),
            event_id: Some(1),
            org_id: Some(3),
            date_sighting: Some(1700000000),
            source: Some("honeypot-1".into()),
            sighting_type: Some(0),
            attribute_uuid: Some("attr-uuid-5678".into()),
        };
        let json = serde_json::to_string(&s).unwrap();
        let back: MispSighting = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    fn sighting_deserialize_misp_format() {
        let json = r#"{
            "id": "42",
            "uuid": "sight-uuid-1234",
            "attribute_id": "7",
            "event_id": "1",
            "org_id": "3",
            "date_sighting": "1700000000",
            "source": "honeypot-1",
            "type": "0",
            "attribute_uuid": "attr-uuid-5678"
        }"#;
        let s: MispSighting = serde_json::from_str(json).unwrap();
        assert_eq!(s.id, Some(42));
        assert_eq!(s.attribute_id, Some(7));
        assert_eq!(s.sighting_type, Some(0));
        assert_eq!(s.source.as_deref(), Some("honeypot-1"));
    }

    #[test]
    fn sighting_type_field_rename() {
        let s = MispSighting::new();
        let json = serde_json::to_string(&s).unwrap();
        let val: serde_json::Value = serde_json::from_str(&json).unwrap();
        // "type" key in JSON, "sighting_type" in Rust
        assert_eq!(val["type"], "0");
        assert!(val.get("sighting_type").is_none());
    }
}
