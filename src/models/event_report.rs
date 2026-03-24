use serde::{Deserialize, Serialize};

use super::serde_helpers::{flexible_bool, string_or_i64_opt};

/// A MISP event report — a markdown document attached to an event.
///
/// Event reports allow analysts to write detailed reports about events,
/// including references to attributes and objects within the event.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MispEventReport {
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

    /// Report title/name.
    pub name: String,

    /// Markdown content of the report.
    #[serde(default)]
    pub content: String,

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
}

impl MispEventReport {
    /// Create a new event report with a name and content.
    pub fn new(name: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            id: None,
            uuid: None,
            event_id: None,
            name: name.into(),
            content: content.into(),
            distribution: None,
            sharing_group_id: None,
            timestamp: None,
            deleted: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_report_new_defaults() {
        let report = MispEventReport::new("Test Report", "# Heading\n\nSome content.");
        assert_eq!(report.name, "Test Report");
        assert_eq!(report.content, "# Heading\n\nSome content.");
        assert!(report.id.is_none());
        assert!(report.event_id.is_none());
        assert!(!report.deleted);
    }

    #[test]
    fn event_report_serde_roundtrip() {
        let report = MispEventReport {
            id: Some(10),
            uuid: Some("report-uuid-1234".into()),
            event_id: Some(1),
            name: "Incident Analysis".into(),
            content: "Detailed analysis of the incident.".into(),
            distribution: Some(0),
            sharing_group_id: Some(0),
            timestamp: Some(1700000000),
            deleted: false,
        };
        let json = serde_json::to_string(&report).unwrap();
        let back: MispEventReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, back);
    }

    #[test]
    fn event_report_deserialize_misp_format() {
        let json = r#"{
            "id": "10",
            "uuid": "report-uuid-1234",
            "event_id": "1",
            "name": "Incident Analysis",
            "content": "Detailed analysis of the incident.",
            "distribution": "0",
            "sharing_group_id": "0",
            "timestamp": "1700000000",
            "deleted": false
        }"#;
        let report: MispEventReport = serde_json::from_str(json).unwrap();
        assert_eq!(report.id, Some(10));
        assert_eq!(report.event_id, Some(1));
        assert_eq!(report.name, "Incident Analysis");
        assert!(!report.deleted);
    }

    #[test]
    fn event_report_deleted_as_string() {
        let json = r#"{
            "id": "5",
            "name": "Deleted Report",
            "content": "",
            "deleted": "1"
        }"#;
        let report: MispEventReport = serde_json::from_str(json).unwrap();
        assert!(report.deleted);
    }
}
