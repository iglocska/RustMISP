use serde::{Deserialize, Serialize};

/// MISP distribution levels controlling who can see shared data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(i32)]
pub enum Distribution {
    /// Your organisation only.
    #[serde(rename = "0")]
    YourOrganisationOnly = 0,
    /// This community only.
    #[serde(rename = "1")]
    ThisCommunityOnly = 1,
    /// Connected communities.
    #[serde(rename = "2")]
    ConnectedCommunities = 2,
    /// All communities.
    #[serde(rename = "3")]
    AllCommunities = 3,
    /// Sharing group.
    #[serde(rename = "4")]
    SharingGroup = 4,
    /// Inherit from parent event.
    #[serde(rename = "5")]
    InheritEvent = 5,
}

/// MISP threat level indicating severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(i32)]
pub enum ThreatLevel {
    /// High threat.
    #[serde(rename = "1")]
    High = 1,
    /// Medium threat.
    #[serde(rename = "2")]
    Medium = 2,
    /// Low threat.
    #[serde(rename = "3")]
    Low = 3,
    /// Undefined threat level.
    #[serde(rename = "4")]
    Undefined = 4,
}

/// MISP analysis state of an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(i32)]
pub enum Analysis {
    /// Initial analysis.
    #[serde(rename = "0")]
    Initial = 0,
    /// Ongoing analysis.
    #[serde(rename = "1")]
    Ongoing = 1,
    /// Analysis complete.
    #[serde(rename = "2")]
    Complete = 2,
}
