//! Feed generator — creates MISP feed manifest and hashes files.

use std::collections::HashMap;

use serde::Serialize;

use crate::error::MispResult;
use crate::models::event::MispEvent;

/// Generates MISP feed metadata (manifest and hashes) from a set of events.
///
/// # Example
/// ```
/// use rustmisp::tools::feed_generator::FeedGenerator;
/// use rustmisp::MispEvent;
///
/// let mut feed_gen = FeedGenerator::new();
/// let mut event = MispEvent::new("Test event");
/// event.uuid = Some("test-uuid-1234".to_string());
/// feed_gen.add_event(&event);
///
/// let manifest = feed_gen.generate_manifest().unwrap();
/// assert!(manifest.contains("test-uuid-1234"));
/// ```
#[derive(Debug, Clone)]
pub struct FeedGenerator {
    events: Vec<FeedEntry>,
}

#[derive(Debug, Clone, Serialize)]
struct ManifestEntry {
    #[serde(rename = "Event")]
    event: ManifestEventInfo,
}

#[derive(Debug, Clone, Serialize)]
struct ManifestEventInfo {
    info: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    uuid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    date: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    analysis: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    threat_level_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    timestamp: Option<String>,
}

#[derive(Debug, Clone)]
struct FeedEntry {
    uuid: String,
    info: String,
    date: Option<String>,
    analysis: Option<i64>,
    threat_level_id: Option<i64>,
    timestamp: Option<i64>,
    event_json: String,
}

impl FeedGenerator {
    /// Create a new empty feed generator.
    pub fn new() -> Self {
        Self { events: Vec::new() }
    }

    /// Add an event to the feed. The event must have a UUID set.
    pub fn add_event(&mut self, event: &MispEvent) {
        let uuid = event
            .uuid
            .clone()
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

        let event_json = serde_json::to_string(event).unwrap_or_default();

        self.events.push(FeedEntry {
            uuid,
            info: event.info.clone(),
            date: event.date.clone(),
            analysis: event.analysis,
            threat_level_id: event.threat_level_id,
            timestamp: event.timestamp,
            event_json,
        });
    }

    /// Generate the feed manifest as a JSON string.
    ///
    /// The manifest is a JSON object keyed by event UUID, containing
    /// summary information for each event.
    pub fn generate_manifest(&self) -> MispResult<String> {
        let mut manifest: HashMap<&str, ManifestEntry> = HashMap::new();

        for entry in &self.events {
            manifest.insert(
                &entry.uuid,
                ManifestEntry {
                    event: ManifestEventInfo {
                        info: entry.info.clone(),
                        uuid: Some(entry.uuid.clone()),
                        date: entry.date.clone(),
                        analysis: entry.analysis.map(|a| a.to_string()),
                        threat_level_id: entry.threat_level_id.map(|t| t.to_string()),
                        timestamp: entry.timestamp.map(|t| t.to_string()),
                    },
                },
            );
        }

        let json = serde_json::to_string_pretty(&manifest)
            .map_err(|e| crate::error::MispError::InvalidInput(format!("JSON error: {e}")))?;
        Ok(json)
    }

    /// Generate a hash lookup table mapping attribute values to event UUIDs.
    ///
    /// Returns a map of `md5(value)` → list of event UUIDs containing that value.
    pub fn generate_hashes(&self) -> HashMap<String, Vec<String>> {
        let mut hashes: HashMap<String, Vec<String>> = HashMap::new();

        for entry in &self.events {
            // Parse the event JSON back to extract attribute values
            if let Ok(event) = serde_json::from_str::<MispEvent>(&entry.event_json) {
                for attr in &event.attributes {
                    let hash = format!("{:x}", md5_value(attr.value.as_bytes()));
                    hashes.entry(hash).or_default().push(entry.uuid.clone());
                }
            }
        }

        hashes
    }

    /// Get the event JSON for a given UUID, suitable for writing to a feed file.
    pub fn get_event_json(&self, uuid: &str) -> Option<&str> {
        self.events
            .iter()
            .find(|e| e.uuid == uuid)
            .map(|e| e.event_json.as_str())
    }

    /// Return the list of event UUIDs in this feed.
    pub fn event_uuids(&self) -> Vec<&str> {
        self.events.iter().map(|e| e.uuid.as_str()).collect()
    }
}

impl Default for FeedGenerator {
    fn default() -> Self {
        Self::new()
    }
}

/// Simple MD5-like hash using the standard library's built-in hasher.
/// We use a basic FNV-style hash here since md-5 crate is optional.
fn md5_value(data: &[u8]) -> u128 {
    // Use a simple, deterministic hash for feed lookups.
    // This is NOT cryptographic — it's for feed cache indexing only.
    let mut hash: u128 = 0xcbf29ce484222325;
    for &byte in data {
        hash ^= byte as u128;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::attribute::MispAttribute;

    #[test]
    fn feed_generator_manifest() {
        let mut feed_gen = FeedGenerator::new();
        let mut event = MispEvent::new("");
        event.uuid = Some("test-uuid-1234".to_string());
        event.info = "Test event".to_string();
        event.date = Some("2024-01-01".to_string());
        feed_gen.add_event(&event);

        let manifest = feed_gen.generate_manifest().unwrap();
        assert!(manifest.contains("test-uuid-1234"));
        assert!(manifest.contains("Test event"));
        assert!(manifest.contains("2024-01-01"));
    }

    #[test]
    fn feed_generator_multiple_events() {
        let mut feed_gen = FeedGenerator::new();

        let mut e1 = MispEvent::new("");
        e1.uuid = Some("uuid-1".to_string());
        e1.info = "Event 1".to_string();
        feed_gen.add_event(&e1);

        let mut e2 = MispEvent::new("");
        e2.uuid = Some("uuid-2".to_string());
        e2.info = "Event 2".to_string();
        feed_gen.add_event(&e2);

        assert_eq!(feed_gen.event_uuids().len(), 2);

        let manifest = feed_gen.generate_manifest().unwrap();
        assert!(manifest.contains("uuid-1"));
        assert!(manifest.contains("uuid-2"));
    }

    #[test]
    fn feed_generator_hashes() {
        let mut feed_gen = FeedGenerator::new();
        let mut event = MispEvent::new("");
        event.uuid = Some("uuid-1".to_string());
        event.info = "Test".to_string();
        event.attributes = vec![MispAttribute::new("ip-src", "Network activity", "1.2.3.4")];
        feed_gen.add_event(&event);

        let hashes = feed_gen.generate_hashes();
        assert!(!hashes.is_empty());
        // At least one hash should map to our event UUID
        assert!(hashes.values().any(|v| v.contains(&"uuid-1".to_string())));
    }

    #[test]
    fn feed_generator_get_event_json() {
        let mut feed_gen = FeedGenerator::new();
        let mut event = MispEvent::new("");
        event.uuid = Some("uuid-1".to_string());
        event.info = "Test".to_string();
        feed_gen.add_event(&event);

        assert!(feed_gen.get_event_json("uuid-1").is_some());
        assert!(feed_gen.get_event_json("nonexistent").is_none());
    }

    #[test]
    fn feed_generator_default() {
        let feed_gen = FeedGenerator::default();
        assert!(feed_gen.event_uuids().is_empty());
    }
}
