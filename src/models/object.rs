use serde::{Deserialize, Serialize};

use super::attribute::MispAttribute;
use super::serde_helpers::{flexible_bool, string_or_i64_opt};

/// A MISP object — a grouping of related attributes with a defined template.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MispObject {
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

    /// Object name (e.g., `"file"`, `"domain-ip"`, `"email"`).
    #[serde(default)]
    pub name: String,

    /// Meta-category (e.g., `"file"`, `"network"`, `"misc"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meta_category: Option<String>,

    /// Description of this object.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// UUID of the object template used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template_uuid: Option<String>,

    /// Version of the object template used.
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub template_version: Option<i64>,

    /// Parent event ID.
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub event_id: Option<i64>,

    /// Distribution level: 0-5.
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

    /// Comment on this object.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,

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

    /// Whether the first_seen/last_seen is set at the object level.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_seen: Option<String>,

    /// Last observation datetime.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<String>,

    /// Attributes belonging to this object.
    #[serde(default, rename = "Attribute", skip_serializing_if = "Vec::is_empty")]
    pub attributes: Vec<MispAttribute>,

    /// References from this object to other objects/attributes.
    #[serde(
        default,
        rename = "ObjectReference",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub references: Vec<MispObjectReference>,
}

impl MispObject {
    /// Create a new object with the given template name.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            id: None,
            uuid: None,
            name: name.into(),
            meta_category: None,
            description: None,
            template_uuid: None,
            template_version: None,
            event_id: None,
            distribution: None,
            sharing_group_id: None,
            comment: None,
            timestamp: None,
            deleted: false,
            first_seen: None,
            last_seen: None,
            attributes: Vec::new(),
            references: Vec::new(),
        }
    }

    /// Add an attribute to this object.
    pub fn add_attribute(&mut self, attr: MispAttribute) {
        self.attributes.push(attr);
    }

    /// Add a reference from this object to another entity.
    pub fn add_reference(&mut self, reference: MispObjectReference) {
        self.references.push(reference);
    }
}

/// A reference linking a MISP object to another object or attribute.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MispObjectReference {
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

    /// Parent object ID.
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub object_id: Option<i64>,

    /// Parent event ID.
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub event_id: Option<i64>,

    /// UUID of the source object.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_uuid: Option<String>,

    /// UUID of the referenced object or attribute.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub referenced_uuid: Option<String>,

    /// ID of the referenced entity.
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub referenced_id: Option<i64>,

    /// Type of the referenced entity (0 = object, 1 = attribute).
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub referenced_type: Option<i64>,

    /// Relationship type (e.g., `"related-to"`, `"derived-from"`, `"dropped-by"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relationship_type: Option<String>,

    /// Comment on this reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,

    /// Unix timestamp.
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub timestamp: Option<i64>,

    /// Soft-deletion flag.
    #[serde(default, with = "flexible_bool")]
    pub deleted: bool,
}

impl MispObjectReference {
    /// Create a new object reference.
    pub fn new(referenced_uuid: impl Into<String>, relationship_type: impl Into<String>) -> Self {
        Self {
            id: None,
            uuid: None,
            object_id: None,
            event_id: None,
            source_uuid: None,
            referenced_uuid: Some(referenced_uuid.into()),
            referenced_id: None,
            referenced_type: None,
            relationship_type: Some(relationship_type.into()),
            comment: None,
            timestamp: None,
            deleted: false,
        }
    }
}

/// A MISP object template definition.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MispObjectTemplate {
    /// Unique numeric identifier.
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub id: Option<i64>,

    /// UUID of the template.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,

    /// Template name (e.g., `"file"`, `"domain-ip"`).
    #[serde(default)]
    pub name: String,

    /// Template version.
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub version: Option<i64>,

    /// Description of the template.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Meta-category.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meta_category: Option<String>,

    /// Whether this template is active.
    #[serde(default, with = "flexible_bool")]
    pub active: bool,

    /// Whether this template is fixed (not editable).
    #[serde(default, with = "flexible_bool")]
    pub fixed: bool,
}

impl MispObjectTemplate {
    /// Create a new object template with the given name.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            id: None,
            uuid: None,
            name: name.into(),
            version: None,
            description: None,
            meta_category: None,
            active: true,
            fixed: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::attribute::MispAttribute;

    #[test]
    fn object_new_defaults() {
        let obj = MispObject::new("file");
        assert_eq!(obj.name, "file");
        assert!(obj.id.is_none());
        assert!(!obj.deleted);
        assert!(obj.attributes.is_empty());
        assert!(obj.references.is_empty());
    }

    #[test]
    fn object_serde_roundtrip() {
        let obj = MispObject {
            id: Some(10),
            uuid: Some("abcd-1234".into()),
            name: "file".into(),
            meta_category: Some("file".into()),
            description: Some("A file object".into()),
            template_uuid: Some("template-uuid-1234".into()),
            template_version: Some(23),
            event_id: Some(1),
            distribution: Some(1),
            sharing_group_id: None,
            comment: Some("test object".into()),
            timestamp: Some(1700000000),
            deleted: false,
            first_seen: None,
            last_seen: None,
            attributes: vec![MispAttribute::new("md5", "Payload delivery", "abc123")],
            references: vec![MispObjectReference::new("ref-uuid-5678", "related-to")],
        };
        let json = serde_json::to_string(&obj).unwrap();
        let back: MispObject = serde_json::from_str(&json).unwrap();
        assert_eq!(obj, back);
    }

    #[test]
    fn object_deserialize_misp_format() {
        let json = r#"{
            "id": "10",
            "uuid": "abcd-1234",
            "name": "file",
            "meta-category": "file",
            "template_uuid": "template-uuid-1234",
            "template_version": "23",
            "event_id": "1",
            "distribution": "1",
            "timestamp": "1700000000",
            "deleted": false,
            "comment": "test",
            "Attribute": [
                {
                    "id": "50",
                    "type": "md5",
                    "category": "Payload delivery",
                    "value": "abc123",
                    "object_relation": "md5",
                    "to_ids": true,
                    "comment": "",
                    "deleted": false,
                    "disable_correlation": false
                }
            ],
            "ObjectReference": [
                {
                    "id": "5",
                    "uuid": "ref-uuid",
                    "object_id": "10",
                    "referenced_uuid": "other-uuid",
                    "referenced_type": "0",
                    "relationship_type": "related-to",
                    "deleted": false
                }
            ]
        }"#;
        let obj: MispObject = serde_json::from_str(json).unwrap();
        assert_eq!(obj.id, Some(10));
        assert_eq!(obj.name, "file");
        assert_eq!(obj.template_version, Some(23));
        assert_eq!(obj.attributes.len(), 1);
        assert_eq!(obj.attributes[0].attr_type, "md5");
        assert_eq!(obj.attributes[0].object_relation.as_deref(), Some("md5"));
        assert_eq!(obj.references.len(), 1);
        assert_eq!(
            obj.references[0].relationship_type.as_deref(),
            Some("related-to")
        );
    }

    #[test]
    fn object_wrapped_response() {
        let json = r#"{"Object": {"id": "15", "name": "domain-ip", "deleted": false}}"#;
        let val: serde_json::Value = serde_json::from_str(json).unwrap();
        let obj: MispObject = serde_json::from_value(val["Object"].clone()).unwrap();
        assert_eq!(obj.id, Some(15));
        assert_eq!(obj.name, "domain-ip");
    }

    #[test]
    fn object_add_attribute_and_reference() {
        let mut obj = MispObject::new("file");
        obj.add_attribute(MispAttribute::new("md5", "Payload delivery", "abc123"));
        obj.add_reference(MispObjectReference::new("other-uuid", "dropped-by"));
        assert_eq!(obj.attributes.len(), 1);
        assert_eq!(obj.references.len(), 1);
    }

    #[test]
    fn object_reference_new_defaults() {
        let r = MispObjectReference::new("target-uuid", "related-to");
        assert_eq!(r.referenced_uuid.as_deref(), Some("target-uuid"));
        assert_eq!(r.relationship_type.as_deref(), Some("related-to"));
        assert!(r.id.is_none());
        assert!(!r.deleted);
    }

    #[test]
    fn object_reference_serde_roundtrip() {
        let r = MispObjectReference {
            id: Some(5),
            uuid: Some("ref-uuid-1".into()),
            object_id: Some(10),
            event_id: Some(1),
            source_uuid: Some("source-uuid".into()),
            referenced_uuid: Some("target-uuid".into()),
            referenced_id: Some(20),
            referenced_type: Some(0),
            relationship_type: Some("related-to".into()),
            comment: Some("test ref".into()),
            timestamp: Some(1700000000),
            deleted: false,
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: MispObjectReference = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn object_template_new_defaults() {
        let t = MispObjectTemplate::new("file");
        assert_eq!(t.name, "file");
        assert!(t.active);
        assert!(!t.fixed);
    }

    #[test]
    fn object_template_serde_roundtrip() {
        let t = MispObjectTemplate {
            id: Some(1),
            uuid: Some("tmpl-uuid".into()),
            name: "file".into(),
            version: Some(23),
            description: Some("File object template".into()),
            meta_category: Some("file".into()),
            active: true,
            fixed: false,
        };
        let json = serde_json::to_string(&t).unwrap();
        let back: MispObjectTemplate = serde_json::from_str(&json).unwrap();
        assert_eq!(t, back);
    }

    #[test]
    fn object_template_deserialize_misp_format() {
        let json = r#"{
            "id": "42",
            "uuid": "tmpl-uuid-42",
            "name": "domain-ip",
            "version": "10",
            "description": "Domain-IP template",
            "meta-category": "network",
            "active": true,
            "fixed": false
        }"#;
        let t: MispObjectTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(t.id, Some(42));
        assert_eq!(t.name, "domain-ip");
        assert_eq!(t.version, Some(10));
        assert!(t.active);
    }
}
