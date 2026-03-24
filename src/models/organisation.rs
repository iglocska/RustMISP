use serde::{Deserialize, Serialize};

use super::serde_helpers::{flexible_bool, string_or_i64_opt};

/// A MISP organisation — represents an entity that owns events and users.
///
/// Organisations are the primary unit of ownership in MISP. Every event,
/// user, and sharing group is associated with an organisation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MispOrganisation {
    /// Unique numeric identifier (set by server).
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub id: Option<i64>,

    /// UUID of the organisation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,

    /// Name of the organisation.
    #[serde(default)]
    pub name: String,

    /// Description of the organisation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Nationality of the organisation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nationality: Option<String>,

    /// Sector the organisation operates in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sector: Option<String>,

    /// Type of the organisation.
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,

    /// Contact information.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contacts: Option<String>,

    /// Whether the organisation is local to this instance.
    #[serde(default, with = "flexible_bool")]
    pub local: bool,

    /// Whether this organisation was created by a user.
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub created_by: Option<i64>,

    /// Landingpage / URL for the organisation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub landingpage: Option<String>,

    /// Number of users in this organisation (read-only, returned by server).
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub user_count: Option<i64>,

    /// Timestamp of creation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub date_created: Option<String>,

    /// Timestamp of last modification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub date_modified: Option<String>,
}

impl MispOrganisation {
    /// Create a new organisation with a name.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            id: None,
            uuid: None,
            name: name.into(),
            description: None,
            nationality: None,
            sector: None,
            type_: None,
            contacts: None,
            local: true,
            created_by: None,
            landingpage: None,
            user_count: None,
            date_created: None,
            date_modified: None,
        }
    }
}

impl Default for MispOrganisation {
    fn default() -> Self {
        Self::new("")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn organisation_new_defaults() {
        let o = MispOrganisation::new("CIRCL");
        assert_eq!(o.name, "CIRCL");
        assert!(o.id.is_none());
        assert!(o.uuid.is_none());
        assert!(o.local);
        assert!(o.description.is_none());
    }

    #[test]
    fn organisation_serde_roundtrip() {
        let o = MispOrganisation {
            id: Some(1),
            uuid: Some("550e8400-e29b-41d4-a716-446655440000".into()),
            name: "CIRCL".into(),
            description: Some("Computer Incident Response Center Luxembourg".into()),
            nationality: Some("Luxembourg".into()),
            sector: Some("Government".into()),
            type_: Some("CERT".into()),
            contacts: Some("info@circl.lu".into()),
            local: true,
            created_by: Some(1),
            landingpage: None,
            user_count: Some(5),
            date_created: Some("2024-01-01".into()),
            date_modified: Some("2024-06-15".into()),
        };
        let json = serde_json::to_string(&o).unwrap();
        let back: MispOrganisation = serde_json::from_str(&json).unwrap();
        assert_eq!(o, back);
    }

    #[test]
    fn organisation_deserialize_misp_format() {
        let json = r#"{
            "id": "42",
            "uuid": "550e8400-e29b-41d4-a716-446655440000",
            "name": "CIRCL",
            "description": "Computer Incident Response Center Luxembourg",
            "nationality": "Luxembourg",
            "sector": "Government",
            "type": "CERT",
            "contacts": "info@circl.lu",
            "local": "1",
            "created_by": "1",
            "user_count": "5"
        }"#;
        let o: MispOrganisation = serde_json::from_str(json).unwrap();
        assert_eq!(o.id, Some(42));
        assert_eq!(o.name, "CIRCL");
        assert_eq!(o.type_, Some("CERT".into()));
        assert!(o.local);
        assert_eq!(o.user_count, Some(5));
    }

    #[test]
    fn organisation_deserialize_minimal() {
        let json = r#"{"name": "Test Org"}"#;
        let o: MispOrganisation = serde_json::from_str(json).unwrap();
        assert_eq!(o.name, "Test Org");
        assert!(o.id.is_none());
        assert!(!o.local);
    }

    #[test]
    fn organisation_type_field_rename() {
        let o = MispOrganisation {
            type_: Some("CERT".into()),
            ..MispOrganisation::new("Test")
        };
        let json = serde_json::to_string(&o).unwrap();
        assert!(json.contains(r#""type":"CERT"#));
        assert!(!json.contains("type_"));
    }
}
