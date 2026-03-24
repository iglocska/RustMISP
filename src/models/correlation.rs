use serde::{Deserialize, Serialize};

use super::serde_helpers::{flexible_bool, string_or_i64_opt};

/// A MISP decaying model — defines how indicator scores decay over time.
///
/// Decaying models allow MISP to automatically reduce the relevance score
/// of indicators based on configurable parameters (lifetime, decay speed, etc.).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MispDecayingModel {
    /// Unique numeric identifier (set by server).
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub id: Option<i64>,

    /// Name of the decaying model.
    #[serde(default)]
    pub name: String,

    /// Model parameters (lifetime, decay_speed, threshold, etc.).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parameters: Option<serde_json::Value>,

    /// Attribute types this model applies to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute_types: Option<Vec<String>>,

    /// Human-readable description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Organisation ID of the model creator.
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub org_id: Option<i64>,

    /// Whether this model is enabled.
    #[serde(default, with = "flexible_bool")]
    pub enabled: bool,

    /// Whether this is a default (built-in) model.
    #[serde(default, with = "flexible_bool")]
    pub all_orgs: bool,
}

impl MispDecayingModel {
    /// Create a new decaying model with a name.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            id: None,
            name: name.into(),
            parameters: None,
            attribute_types: None,
            description: None,
            org_id: None,
            enabled: false,
            all_orgs: false,
        }
    }
}

impl Default for MispDecayingModel {
    fn default() -> Self {
        Self::new("")
    }
}

/// A MISP correlation exclusion — a value that should be excluded from
/// automatic correlation (e.g., common infrastructure like 8.8.8.8).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MispCorrelationExclusion {
    /// Unique numeric identifier (set by server).
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub id: Option<i64>,

    /// The value to exclude from correlation.
    #[serde(default)]
    pub value: String,

    /// Optional comment explaining the exclusion.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

impl MispCorrelationExclusion {
    /// Create a new correlation exclusion for a value.
    pub fn new(value: impl Into<String>) -> Self {
        Self {
            id: None,
            value: value.into(),
            comment: None,
        }
    }
}

impl Default for MispCorrelationExclusion {
    fn default() -> Self {
        Self::new("")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── MispDecayingModel tests ─────────────────────────────────────

    #[test]
    fn decaying_model_new_defaults() {
        let m = MispDecayingModel::new("NIDS Simple Decaying Model");
        assert_eq!(m.name, "NIDS Simple Decaying Model");
        assert!(m.id.is_none());
        assert!(!m.enabled);
        assert!(!m.all_orgs);
    }

    #[test]
    fn decaying_model_serde_roundtrip() {
        let m = MispDecayingModel {
            id: Some(1),
            name: "NIDS Simple Decaying Model".into(),
            parameters: Some(serde_json::json!({
                "lifetime": 365,
                "decay_speed": 1.0,
                "threshold": 0
            })),
            attribute_types: Some(vec!["ip-src".into(), "ip-dst".into()]),
            description: Some("Simple decaying model for NIDS".into()),
            org_id: Some(1),
            enabled: true,
            all_orgs: true,
        };
        let json = serde_json::to_string(&m).unwrap();
        let back: MispDecayingModel = serde_json::from_str(&json).unwrap();
        assert_eq!(m, back);
    }

    #[test]
    fn decaying_model_deserialize_misp_format() {
        let json = r#"{
            "id": "1",
            "name": "NIDS Simple Decaying Model",
            "parameters": {"lifetime": 365, "decay_speed": 1.0, "threshold": 0},
            "attribute_types": ["ip-src", "ip-dst"],
            "description": "Simple decaying model for NIDS",
            "org_id": "1",
            "enabled": "1",
            "all_orgs": "1"
        }"#;
        let m: MispDecayingModel = serde_json::from_str(json).unwrap();
        assert_eq!(m.id, Some(1));
        assert_eq!(m.name, "NIDS Simple Decaying Model");
        assert!(m.enabled);
        assert!(m.all_orgs);
        assert_eq!(m.attribute_types.as_ref().unwrap().len(), 2);
    }

    #[test]
    fn decaying_model_deserialize_boolean_formats() {
        let json = r#"{
            "name": "test",
            "enabled": true,
            "all_orgs": "false"
        }"#;
        let m: MispDecayingModel = serde_json::from_str(json).unwrap();
        assert!(m.enabled);
        assert!(!m.all_orgs);
    }

    // ── MispCorrelationExclusion tests ──────────────────────────────

    #[test]
    fn correlation_exclusion_new_defaults() {
        let e = MispCorrelationExclusion::new("8.8.8.8");
        assert_eq!(e.value, "8.8.8.8");
        assert!(e.id.is_none());
        assert!(e.comment.is_none());
    }

    #[test]
    fn correlation_exclusion_serde_roundtrip() {
        let e = MispCorrelationExclusion {
            id: Some(5),
            value: "8.8.8.8".into(),
            comment: Some("Google public DNS".into()),
        };
        let json = serde_json::to_string(&e).unwrap();
        let back: MispCorrelationExclusion = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
    }

    #[test]
    fn correlation_exclusion_deserialize_misp_format() {
        let json = r#"{
            "id": "5",
            "value": "8.8.8.8",
            "comment": "Google public DNS"
        }"#;
        let e: MispCorrelationExclusion = serde_json::from_str(json).unwrap();
        assert_eq!(e.id, Some(5));
        assert_eq!(e.value, "8.8.8.8");
        assert_eq!(e.comment.as_deref(), Some("Google public DNS"));
    }
}
