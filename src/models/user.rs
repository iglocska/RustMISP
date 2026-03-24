use serde::{Deserialize, Serialize};

use super::organisation::MispOrganisation;
use super::serde_helpers::{flexible_bool, flexible_bool_opt, string_or_i64_opt};

/// A MISP user account.
///
/// Users belong to an organisation and have a role that determines
/// their permissions on the MISP instance.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MispUser {
    /// Unique numeric identifier (set by server).
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub id: Option<i64>,

    /// Email address (used as login identifier).
    #[serde(default)]
    pub email: String,

    /// Organisation ID this user belongs to.
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub org_id: Option<i64>,

    /// Role ID assigned to this user.
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub role_id: Option<i64>,

    /// API authentication key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authkey: Option<String>,

    /// ID of the user who invited this user.
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub invited_by: Option<i64>,

    /// GPG public key for encrypted notifications.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpgkey: Option<String>,

    /// NIDS SID (Network IDS Signature ID).
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub nids_sid: Option<i64>,

    /// Whether the user has accepted the terms of use.
    #[serde(default, with = "flexible_bool")]
    pub termsaccepted: bool,

    /// Whether the user receives automatic email alerts for new events.
    #[serde(default, with = "flexible_bool")]
    pub autoalert: bool,

    /// Whether the user receives contact alerts.
    #[serde(default, with = "flexible_bool")]
    pub contactalert: bool,

    /// Whether the user account is disabled.
    #[serde(default, with = "flexible_bool")]
    pub disabled: bool,

    /// Password (only used when creating/updating, never returned by server).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,

    /// Whether to change the password on next login.
    #[serde(
        default,
        with = "flexible_bool_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub change_pw: Option<bool>,

    /// S/MIME certificate for encrypted notifications.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certif_public: Option<String>,

    /// Whether notifications are enabled.
    #[serde(
        default,
        with = "flexible_bool_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub notification_daily: Option<bool>,

    /// Whether weekly notifications are enabled.
    #[serde(
        default,
        with = "flexible_bool_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub notification_weekly: Option<bool>,

    /// Whether monthly notifications are enabled.
    #[serde(
        default,
        with = "flexible_bool_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub notification_monthly: Option<bool>,

    /// Timestamp of last login.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_login: Option<String>,

    /// Date the user was created.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub date_created: Option<String>,

    /// Date the user was last modified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub date_modified: Option<String>,

    /// Nested Organisation object (read-only, returned by server).
    #[serde(
        default,
        rename = "Organisation",
        skip_serializing_if = "Option::is_none"
    )]
    pub organisation: Option<MispOrganisation>,

    /// Nested Role object (read-only, returned by server).
    #[serde(default, rename = "Role", skip_serializing_if = "Option::is_none")]
    pub role: Option<MispRole>,
}

impl MispUser {
    /// Create a new user with an email address.
    pub fn new(email: impl Into<String>) -> Self {
        Self {
            id: None,
            email: email.into(),
            org_id: None,
            role_id: None,
            authkey: None,
            invited_by: None,
            gpgkey: None,
            nids_sid: None,
            termsaccepted: false,
            autoalert: false,
            contactalert: false,
            disabled: false,
            password: None,
            change_pw: None,
            certif_public: None,
            notification_daily: None,
            notification_weekly: None,
            notification_monthly: None,
            last_login: None,
            date_created: None,
            date_modified: None,
            organisation: None,
            role: None,
        }
    }
}

impl Default for MispUser {
    fn default() -> Self {
        Self::new("")
    }
}

/// A MISP role — defines permissions for users.
///
/// Roles control what actions a user can perform, including viewing,
/// editing, publishing, and administrating MISP data.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MispRole {
    /// Unique numeric identifier (set by server).
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub id: Option<i64>,

    /// Name of the role.
    #[serde(default)]
    pub name: String,

    /// Whether this is the default role for new users.
    #[serde(default, with = "flexible_bool")]
    pub default_role: bool,

    /// Permission to add events.
    #[serde(default, with = "flexible_bool")]
    pub perm_add: bool,

    /// Permission to modify events.
    #[serde(default, with = "flexible_bool")]
    pub perm_modify: bool,

    /// Permission to modify events from other organisations.
    #[serde(default, with = "flexible_bool")]
    pub perm_modify_org: bool,

    /// Permission to publish events.
    #[serde(default, with = "flexible_bool")]
    pub perm_publish: bool,

    /// Permission to publish via ZMQ.
    #[serde(default, with = "flexible_bool")]
    pub perm_publish_zmq: bool,

    /// Permission to publish via Kafka.
    #[serde(default, with = "flexible_bool")]
    pub perm_publish_kafka: bool,

    /// Permission to delegate events.
    #[serde(default, with = "flexible_bool")]
    pub perm_delegate: bool,

    /// Permission to sync (push/pull).
    #[serde(default, with = "flexible_bool")]
    pub perm_sync: bool,

    /// Permission to administer the MISP instance.
    #[serde(default, with = "flexible_bool")]
    pub perm_admin: bool,

    /// Permission to perform audit actions.
    #[serde(default, with = "flexible_bool")]
    pub perm_audit: bool,

    /// Full permission to manage the entire instance.
    #[serde(default, with = "flexible_bool")]
    pub perm_full: bool,

    /// Permission to manage auth keys.
    #[serde(default, with = "flexible_bool")]
    pub perm_auth: bool,

    /// Permission to access site admin functions.
    #[serde(default, with = "flexible_bool")]
    pub perm_site_admin: bool,

    /// Permission to manage regex.
    #[serde(default, with = "flexible_bool")]
    pub perm_regexp_access: bool,

    /// Permission to tag events/attributes.
    #[serde(default, with = "flexible_bool")]
    pub perm_tagger: bool,

    /// Permission to access the template editor.
    #[serde(default, with = "flexible_bool")]
    pub perm_template: bool,

    /// Permission to manage sharing groups.
    #[serde(default, with = "flexible_bool")]
    pub perm_sharing_group: bool,

    /// Permission to tag with galaxy clusters.
    #[serde(default, with = "flexible_bool")]
    pub perm_tag_editor: bool,

    /// Permission to manage sightings.
    #[serde(default, with = "flexible_bool")]
    pub perm_sighting: bool,

    /// Permission to manage object templates.
    #[serde(default, with = "flexible_bool")]
    pub perm_object_template: bool,

    /// Whether users with this role are restricted to their own organisation.
    #[serde(default, with = "flexible_bool")]
    pub restrict_org_admin: bool,

    /// Memory limit for this role.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_limit: Option<String>,

    /// Max execution time for this role.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_execution_time: Option<String>,

    /// Permission level (read-only bitmask value).
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub permission: Option<i64>,
}

impl MispRole {
    /// Create a new role with a name.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            id: None,
            name: name.into(),
            default_role: false,
            perm_add: false,
            perm_modify: false,
            perm_modify_org: false,
            perm_publish: false,
            perm_publish_zmq: false,
            perm_publish_kafka: false,
            perm_delegate: false,
            perm_sync: false,
            perm_admin: false,
            perm_audit: false,
            perm_full: false,
            perm_auth: false,
            perm_site_admin: false,
            perm_regexp_access: false,
            perm_tagger: false,
            perm_template: false,
            perm_sharing_group: false,
            perm_tag_editor: false,
            perm_sighting: false,
            perm_object_template: false,
            restrict_org_admin: false,
            memory_limit: None,
            max_execution_time: None,
            permission: None,
        }
    }
}

impl Default for MispRole {
    fn default() -> Self {
        Self::new("")
    }
}

/// A MISP inbox entry — represents a pending registration or request.
///
/// Inbox entries are created when users self-register or request
/// access to a MISP instance.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MispInbox {
    /// Unique numeric identifier (set by server).
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub id: Option<i64>,

    /// Type of inbox entry (e.g., "Registration").
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,

    /// Title of the inbox entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,

    /// IP address of the requester.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,

    /// User agent of the requester.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,

    /// Email address of the requester.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,

    /// Organisation name of the requester.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org: Option<String>,

    /// Additional data as a JSON value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,

    /// Comment from the requester.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,

    /// Timestamp of creation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
}

impl MispInbox {
    /// Create a new inbox entry.
    pub fn new() -> Self {
        Self {
            id: None,
            type_: None,
            title: None,
            ip: None,
            user_agent: None,
            email: None,
            org: None,
            data: None,
            comment: None,
            timestamp: None,
        }
    }
}

impl Default for MispInbox {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── MispUser tests ──────────────────────────────────────────────

    #[test]
    fn user_new_defaults() {
        let u = MispUser::new("admin@misp.local");
        assert_eq!(u.email, "admin@misp.local");
        assert!(u.id.is_none());
        assert!(!u.disabled);
        assert!(!u.termsaccepted);
        assert!(!u.autoalert);
    }

    #[test]
    fn user_serde_roundtrip() {
        let u = MispUser {
            id: Some(1),
            email: "admin@misp.local".into(),
            org_id: Some(1),
            role_id: Some(1),
            authkey: Some("abc123".into()),
            invited_by: Some(0),
            gpgkey: None,
            nids_sid: Some(4000000),
            termsaccepted: true,
            autoalert: true,
            contactalert: true,
            disabled: false,
            password: None,
            change_pw: Some(false),
            certif_public: None,
            notification_daily: Some(true),
            notification_weekly: None,
            notification_monthly: None,
            last_login: Some("1711900000".into()),
            date_created: None,
            date_modified: None,
            organisation: None,
            role: None,
        };
        let json = serde_json::to_string(&u).unwrap();
        let back: MispUser = serde_json::from_str(&json).unwrap();
        assert_eq!(u, back);
    }

    #[test]
    fn user_deserialize_misp_format() {
        let json = r#"{
            "id": "1",
            "email": "admin@misp.local",
            "org_id": "1",
            "role_id": "1",
            "authkey": "abc123def456",
            "invited_by": "0",
            "nids_sid": "4000000",
            "termsaccepted": "1",
            "autoalert": "1",
            "contactalert": "0",
            "disabled": "0",
            "change_pw": "0"
        }"#;
        let u: MispUser = serde_json::from_str(json).unwrap();
        assert_eq!(u.id, Some(1));
        assert_eq!(u.email, "admin@misp.local");
        assert_eq!(u.org_id, Some(1));
        assert!(u.termsaccepted);
        assert!(u.autoalert);
        assert!(!u.contactalert);
        assert!(!u.disabled);
        assert_eq!(u.change_pw, Some(false));
    }

    #[test]
    fn user_deserialize_with_nested_org_and_role() {
        let json = r#"{
            "id": "1",
            "email": "admin@misp.local",
            "org_id": "1",
            "role_id": "1",
            "termsaccepted": true,
            "autoalert": false,
            "contactalert": false,
            "disabled": false,
            "Organisation": {
                "id": "1",
                "name": "ORGNAME",
                "uuid": "550e8400-e29b-41d4-a716-446655440000"
            },
            "Role": {
                "id": "1",
                "name": "admin",
                "perm_add": "1",
                "perm_modify": "1",
                "perm_publish": "1"
            }
        }"#;
        let u: MispUser = serde_json::from_str(json).unwrap();
        assert_eq!(u.id, Some(1));
        let org = u.organisation.unwrap();
        assert_eq!(org.name, "ORGNAME");
        let role = u.role.unwrap();
        assert_eq!(role.name, "admin");
        assert!(role.perm_publish);
    }

    #[test]
    fn user_deserialize_minimal() {
        let json = r#"{"email": "test@test.com"}"#;
        let u: MispUser = serde_json::from_str(json).unwrap();
        assert_eq!(u.email, "test@test.com");
        assert!(u.id.is_none());
    }

    // ── MispRole tests ──────────────────────────────────────────────

    #[test]
    fn role_new_defaults() {
        let r = MispRole::new("Analyst");
        assert_eq!(r.name, "Analyst");
        assert!(r.id.is_none());
        assert!(!r.perm_add);
        assert!(!r.perm_admin);
        assert!(!r.default_role);
    }

    #[test]
    fn role_serde_roundtrip() {
        let r = MispRole {
            id: Some(3),
            name: "Org Admin".into(),
            default_role: false,
            perm_add: true,
            perm_modify: true,
            perm_modify_org: true,
            perm_publish: true,
            perm_publish_zmq: false,
            perm_publish_kafka: false,
            perm_delegate: false,
            perm_sync: false,
            perm_admin: true,
            perm_audit: false,
            perm_full: false,
            perm_auth: true,
            perm_site_admin: false,
            perm_regexp_access: false,
            perm_tagger: true,
            perm_template: false,
            perm_sharing_group: true,
            perm_tag_editor: true,
            perm_sighting: true,
            perm_object_template: false,
            restrict_org_admin: false,
            memory_limit: None,
            max_execution_time: None,
            permission: Some(3),
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: MispRole = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn role_deserialize_misp_format() {
        let json = r#"{
            "id": "1",
            "name": "admin",
            "default_role": "0",
            "perm_add": "1",
            "perm_modify": "1",
            "perm_modify_org": "1",
            "perm_publish": "1",
            "perm_sync": "1",
            "perm_admin": "1",
            "perm_audit": "1",
            "perm_full": "0",
            "perm_auth": "1",
            "perm_site_admin": "1",
            "perm_regexp_access": "0",
            "perm_tagger": "1",
            "perm_template": "0",
            "perm_sharing_group": "1",
            "perm_tag_editor": "1",
            "perm_sighting": "1",
            "perm_object_template": "0",
            "perm_delegate": "0",
            "perm_publish_zmq": "0",
            "perm_publish_kafka": "0",
            "restrict_org_admin": "0",
            "permission": "3"
        }"#;
        let r: MispRole = serde_json::from_str(json).unwrap();
        assert_eq!(r.id, Some(1));
        assert_eq!(r.name, "admin");
        assert!(r.perm_add);
        assert!(r.perm_site_admin);
        assert!(!r.perm_full);
        assert_eq!(r.permission, Some(3));
    }

    #[test]
    fn role_deserialize_minimal() {
        let json = r#"{"name": "Read Only"}"#;
        let r: MispRole = serde_json::from_str(json).unwrap();
        assert_eq!(r.name, "Read Only");
        assert!(r.id.is_none());
        assert!(!r.perm_add);
    }

    // ── MispInbox tests ─────────────────────────────────────────────

    #[test]
    fn inbox_new_defaults() {
        let i = MispInbox::new();
        assert!(i.id.is_none());
        assert!(i.type_.is_none());
        assert!(i.email.is_none());
    }

    #[test]
    fn inbox_serde_roundtrip() {
        let i = MispInbox {
            id: Some(1),
            type_: Some("Registration".into()),
            title: Some("User registration".into()),
            ip: Some("192.168.1.1".into()),
            user_agent: Some("Mozilla/5.0".into()),
            email: Some("newuser@example.com".into()),
            org: Some("Example Org".into()),
            data: Some(serde_json::json!({"org_name": "Example Org"})),
            comment: Some("Please approve".into()),
            timestamp: Some("1711900000".into()),
        };
        let json = serde_json::to_string(&i).unwrap();
        let back: MispInbox = serde_json::from_str(&json).unwrap();
        assert_eq!(i, back);
    }

    #[test]
    fn inbox_deserialize_misp_format() {
        let json = r#"{
            "id": "5",
            "type": "Registration",
            "title": "User registration",
            "ip": "10.0.0.1",
            "email": "user@example.com",
            "org": "Test Org",
            "comment": "Please add me"
        }"#;
        let i: MispInbox = serde_json::from_str(json).unwrap();
        assert_eq!(i.id, Some(5));
        assert_eq!(i.type_, Some("Registration".into()));
        assert_eq!(i.email, Some("user@example.com".into()));
    }
}
