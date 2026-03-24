use serde::{Deserialize, Serialize};

use super::serde_helpers::{flexible_bool, string_or_i64_opt};

/// A MISP tag that can be attached to events, attributes, or other entities.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MispTag {
    /// Unique numeric identifier (set by server).
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub id: Option<i64>,

    /// Tag name (e.g., `"tlp:green"`, `"osint"`). Required.
    pub name: String,

    /// Hex colour code (e.g., `"#ffffff"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub colour: Option<String>,

    /// Whether this tag is exported during synchronisation.
    #[serde(default = "default_true", with = "flexible_bool")]
    pub exportable: bool,

    /// Organisation ID that owns this tag (0 = shared).
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub org_id: Option<i64>,

    /// User ID that created this tag.
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub user_id: Option<i64>,

    /// Whether to hide this tag from the tag selection UI.
    #[serde(default, with = "flexible_bool")]
    pub hide_tag: bool,

    /// Numeric value associated with the tag (for sorting/scoring).
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub numerical_value: Option<i64>,

    /// Whether this tag represents a galaxy cluster.
    #[serde(default, with = "flexible_bool")]
    pub is_galaxy: bool,

    /// Whether this tag is a custom galaxy.
    #[serde(default, with = "flexible_bool")]
    pub is_custom_galaxy: bool,

    /// Whether this tag is local-only (not synced).
    #[serde(default, with = "flexible_bool")]
    pub local_only: bool,

    /// Whether this tag was applied locally to an entity.
    #[serde(default, with = "flexible_bool")]
    pub local: bool,

    /// Relationship type (when used in galaxy context).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relationship_type: Option<String>,
}

fn default_true() -> bool {
    true
}

impl MispTag {
    /// Create a new tag with just a name. Other fields use defaults.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            id: None,
            name: name.into(),
            colour: None,
            exportable: true,
            org_id: None,
            user_id: None,
            hide_tag: false,
            numerical_value: None,
            is_galaxy: false,
            is_custom_galaxy: false,
            local_only: false,
            local: false,
            relationship_type: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_new_defaults() {
        let tag = MispTag::new("tlp:green");
        assert_eq!(tag.name, "tlp:green");
        assert!(tag.exportable);
        assert!(!tag.hide_tag);
        assert!(tag.id.is_none());
    }

    #[test]
    fn tag_serde_roundtrip() {
        let tag = MispTag {
            id: Some(23),
            name: "osint:source-type=\"blog-post\"".into(),
            colour: Some("#004646".into()),
            exportable: true,
            org_id: Some(1),
            user_id: None,
            hide_tag: false,
            numerical_value: None,
            is_galaxy: false,
            is_custom_galaxy: false,
            local_only: false,
            local: true,
            relationship_type: None,
        };
        let json = serde_json::to_string(&tag).unwrap();
        let back: MispTag = serde_json::from_str(&json).unwrap();
        assert_eq!(tag, back);
    }

    #[test]
    fn tag_deserialize_misp_format() {
        let json = r##"{
            "id": "23",
            "name": "tlp:green",
            "colour": "#339900",
            "exportable": 1,
            "hide_tag": 0,
            "org_id": "0",
            "user_id": "0",
            "numerical_value": null,
            "is_galaxy": false,
            "is_custom_galaxy": false,
            "local_only": false,
            "local": 0
        }"##;
        let tag: MispTag = serde_json::from_str(json).unwrap();
        assert_eq!(tag.id, Some(23));
        assert_eq!(tag.name, "tlp:green");
        assert_eq!(tag.colour.as_deref(), Some("#339900"));
        assert!(tag.exportable);
        assert!(!tag.hide_tag);
        assert!(!tag.local);
    }

    #[test]
    fn tag_deserialize_minimal() {
        let json = r#"{"name": "osint"}"#;
        let tag: MispTag = serde_json::from_str(json).unwrap();
        assert_eq!(tag.name, "osint");
        assert!(tag.id.is_none());
        assert!(tag.exportable); // default true
    }
}
