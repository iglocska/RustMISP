use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

use serde::Deserialize;

use crate::error::{MispError, MispResult};

/// Raw structure matching the `describeTypes.json` file.
#[derive(Debug, Deserialize)]
struct DescribeTypesFile {
    result: DescribeTypesResult,
}

#[derive(Debug, Deserialize)]
struct DescribeTypesResult {
    sane_defaults: HashMap<String, SaneDefault>,
    types: Vec<String>,
    categories: Vec<String>,
    category_type_mappings: HashMap<String, Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct SaneDefault {
    default_category: String,
    to_ids: u8,
}

/// Cached validation schema loaded from `describeTypes.json`.
pub struct ValidationSchema {
    /// Set of all valid attribute types.
    pub types: HashSet<String>,
    /// Set of all valid categories.
    pub categories: HashSet<String>,
    /// Maps each category to the set of valid attribute types for that category.
    pub category_type_mappings: HashMap<String, HashSet<String>>,
    /// Maps each attribute type to its default category.
    pub default_categories: HashMap<String, String>,
    /// Maps each attribute type to its default `to_ids` flag.
    pub default_to_ids: HashMap<String, bool>,
}

static SCHEMA: LazyLock<ValidationSchema> = LazyLock::new(|| {
    let data = include_str!("../data/describeTypes.json");
    let file: DescribeTypesFile =
        serde_json::from_str(data).expect("Failed to parse bundled describeTypes.json");
    let r = file.result;

    let types: HashSet<String> = r.types.into_iter().collect();
    let categories: HashSet<String> = r.categories.into_iter().collect();
    let category_type_mappings: HashMap<String, HashSet<String>> = r
        .category_type_mappings
        .into_iter()
        .map(|(k, v)| (k, v.into_iter().collect()))
        .collect();
    let default_categories: HashMap<String, String> = r
        .sane_defaults
        .iter()
        .map(|(k, v)| (k.clone(), v.default_category.clone()))
        .collect();
    let default_to_ids: HashMap<String, bool> = r
        .sane_defaults
        .into_iter()
        .map(|(k, v)| (k, v.to_ids != 0))
        .collect();

    ValidationSchema {
        types,
        categories,
        category_type_mappings,
        default_categories,
        default_to_ids,
    }
});

/// Returns a reference to the global validation schema.
pub fn schema() -> &'static ValidationSchema {
    &SCHEMA
}

/// Validate that the given string is a known MISP attribute type.
pub fn validate_type(attr_type: &str) -> MispResult<()> {
    if schema().types.contains(attr_type) {
        Ok(())
    } else {
        Err(MispError::InvalidInput(format!(
            "Unknown attribute type: {attr_type}"
        )))
    }
}

/// Validate that the given string is a known MISP category.
pub fn validate_category(category: &str) -> MispResult<()> {
    if schema().categories.contains(category) {
        Ok(())
    } else {
        Err(MispError::InvalidInput(format!(
            "Unknown category: {category}"
        )))
    }
}

/// Validate that a type is valid for the given category.
pub fn validate_type_category_pair(attr_type: &str, category: &str) -> MispResult<()> {
    validate_type(attr_type)?;
    validate_category(category)?;
    if let Some(valid_types) = schema().category_type_mappings.get(category) {
        if valid_types.contains(attr_type) {
            Ok(())
        } else {
            Err(MispError::InvalidInput(format!(
                "Type '{attr_type}' is not valid for category '{category}'"
            )))
        }
    } else {
        Err(MispError::InvalidInput(format!(
            "No type mappings for category: {category}"
        )))
    }
}

/// Get the default category for a given attribute type.
pub fn get_default_category(attr_type: &str) -> Option<&'static str> {
    schema()
        .default_categories
        .get(attr_type)
        .map(|s| s.as_str())
}

/// Get the default `to_ids` flag for a given attribute type.
pub fn get_default_to_ids(attr_type: &str) -> Option<bool> {
    schema().default_to_ids.get(attr_type).copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_loads_types() {
        let s = schema();
        assert!(s.types.contains("md5"));
        assert!(s.types.contains("sha256"));
        assert!(s.types.contains("ip-src"));
        assert!(s.types.contains("domain"));
        assert!(s.types.contains("url"));
        assert!(s.types.len() >= 190);
    }

    #[test]
    fn schema_loads_categories() {
        let s = schema();
        assert!(s.categories.contains("Payload delivery"));
        assert!(s.categories.contains("Network activity"));
        assert!(s.categories.contains("Other"));
        assert_eq!(s.categories.len(), 16);
    }

    #[test]
    fn validate_type_ok() {
        assert!(validate_type("md5").is_ok());
        assert!(validate_type("ip-src").is_ok());
    }

    #[test]
    fn validate_type_unknown() {
        assert!(validate_type("not-a-real-type").is_err());
    }

    #[test]
    fn validate_category_ok() {
        assert!(validate_category("Payload delivery").is_ok());
    }

    #[test]
    fn validate_category_unknown() {
        assert!(validate_category("Fake category").is_err());
    }

    #[test]
    fn validate_pair_ok() {
        assert!(validate_type_category_pair("md5", "Payload delivery").is_ok());
        assert!(validate_type_category_pair("ip-src", "Network activity").is_ok());
    }

    #[test]
    fn validate_pair_mismatch() {
        // md5 should not be valid for "Person" category
        assert!(validate_type_category_pair("md5", "Person").is_err());
    }

    #[test]
    fn default_category_known() {
        assert_eq!(get_default_category("md5"), Some("Payload delivery"));
        assert_eq!(get_default_category("ip-src"), Some("Network activity"));
    }

    #[test]
    fn default_category_unknown() {
        assert_eq!(get_default_category("not-a-type"), None);
    }

    #[test]
    fn default_to_ids_known() {
        assert_eq!(get_default_to_ids("md5"), Some(true));
        assert_eq!(get_default_to_ids("email-subject"), Some(false));
    }
}
