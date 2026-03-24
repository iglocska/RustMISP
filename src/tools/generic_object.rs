//! Generic object generator for building arbitrary MISP objects.

use crate::error::MispResult;
use crate::models::attribute::MispAttribute;
use crate::models::object::{MispObject, MispObjectReference};
use crate::validation;

use super::MispObjectGenerator;

/// A generic object generator that builds arbitrary MISP objects using a
/// builder pattern.
///
/// # Example
/// ```
/// use rustmisp::tools::generic_object::GenericObjectGenerator;
/// use rustmisp::tools::MispObjectGenerator;
///
/// let obj = GenericObjectGenerator::new("domain-ip")
///     .add_attribute("domain", "example.com")
///     .add_attribute("ip", "1.2.3.4")
///     .generate()
///     .unwrap();
///
/// assert_eq!(obj.name, "domain-ip");
/// assert_eq!(obj.attributes.len(), 2);
/// ```
#[derive(Debug, Clone)]
pub struct GenericObjectGenerator {
    name: String,
    attributes: Vec<AttributeEntry>,
    references: Vec<ReferenceEntry>,
    comment: Option<String>,
    distribution: Option<i64>,
}

#[derive(Debug, Clone)]
struct AttributeEntry {
    object_relation: String,
    value: String,
    attr_type: Option<String>,
    category: Option<String>,
    to_ids: Option<bool>,
    comment: Option<String>,
    disable_correlation: Option<bool>,
}

#[derive(Debug, Clone)]
struct ReferenceEntry {
    referenced_uuid: String,
    relationship_type: String,
    comment: Option<String>,
}

impl GenericObjectGenerator {
    /// Create a new generator for an object with the given template name.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            attributes: Vec::new(),
            references: Vec::new(),
            comment: None,
            distribution: None,
        }
    }

    /// Add an attribute with the given object relation and value.
    ///
    /// The attribute type defaults to the object relation name, and the
    /// category is looked up from `describeTypes.json` sane defaults.
    pub fn add_attribute(
        mut self,
        object_relation: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        self.attributes.push(AttributeEntry {
            object_relation: object_relation.into(),
            value: value.into(),
            attr_type: None,
            category: None,
            to_ids: None,
            comment: None,
            disable_correlation: None,
        });
        self
    }

    /// Add an attribute with explicit type and category.
    pub fn add_attribute_full(
        mut self,
        object_relation: impl Into<String>,
        attr_type: impl Into<String>,
        category: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        self.attributes.push(AttributeEntry {
            object_relation: object_relation.into(),
            value: value.into(),
            attr_type: Some(attr_type.into()),
            category: Some(category.into()),
            to_ids: None,
            comment: None,
            disable_correlation: None,
        });
        self
    }

    /// Add a reference to another object/attribute by UUID.
    pub fn add_reference(
        mut self,
        referenced_uuid: impl Into<String>,
        relationship_type: impl Into<String>,
    ) -> Self {
        self.references.push(ReferenceEntry {
            referenced_uuid: referenced_uuid.into(),
            relationship_type: relationship_type.into(),
            comment: None,
        });
        self
    }

    /// Set a comment on the object.
    pub fn comment(mut self, comment: impl Into<String>) -> Self {
        self.comment = Some(comment.into());
        self
    }

    /// Set the distribution level.
    pub fn distribution(mut self, distribution: i64) -> Self {
        self.distribution = Some(distribution);
        self
    }
}

impl MispObjectGenerator for GenericObjectGenerator {
    fn template_name(&self) -> &str {
        &self.name
    }

    fn generate(&self) -> MispResult<MispObject> {
        let mut obj = MispObject::new(&self.name);
        obj.comment = self.comment.clone();
        obj.distribution = self.distribution;

        for entry in &self.attributes {
            let attr_type = entry.attr_type.as_deref().unwrap_or(&entry.object_relation);
            let category = match &entry.category {
                Some(c) => c.clone(),
                None => validation::get_default_category(attr_type)
                    .unwrap_or("Other")
                    .to_string(),
            };
            let to_ids = entry
                .to_ids
                .unwrap_or_else(|| validation::get_default_to_ids(attr_type).unwrap_or(false));

            let mut attr = MispAttribute::new(attr_type, &category, &entry.value);
            attr.object_relation = Some(entry.object_relation.clone());
            attr.to_ids = to_ids;
            if let Some(ref c) = entry.comment {
                attr.comment = c.clone();
            }
            if let Some(dc) = entry.disable_correlation {
                attr.disable_correlation = dc;
            }
            obj.add_attribute(attr);
        }

        for entry in &self.references {
            let mut reference =
                MispObjectReference::new(&entry.referenced_uuid, &entry.relationship_type);
            reference.comment = entry.comment.clone();
            obj.add_reference(reference);
        }

        Ok(obj)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generic_object_basic() {
        let obj = GenericObjectGenerator::new("domain-ip")
            .add_attribute("domain", "example.com")
            .add_attribute("ip", "1.2.3.4")
            .generate()
            .unwrap();
        assert_eq!(obj.name, "domain-ip");
        assert_eq!(obj.attributes.len(), 2);
        assert_eq!(obj.attributes[0].object_relation.as_deref(), Some("domain"));
        assert_eq!(obj.attributes[0].value, "example.com");
        assert_eq!(obj.attributes[1].object_relation.as_deref(), Some("ip"));
        assert_eq!(obj.attributes[1].value, "1.2.3.4");
    }

    #[test]
    fn generic_object_with_type_and_category() {
        let obj = GenericObjectGenerator::new("file")
            .add_attribute_full("md5", "md5", "Payload delivery", "abc123")
            .generate()
            .unwrap();
        assert_eq!(obj.attributes[0].attr_type, "md5");
        assert_eq!(obj.attributes[0].category, "Payload delivery");
    }

    #[test]
    fn generic_object_default_category_lookup() {
        let obj = GenericObjectGenerator::new("file")
            .add_attribute("md5", "d41d8cd98f00b204e9800998ecf8427e")
            .generate()
            .unwrap();
        assert_eq!(obj.attributes[0].category, "Payload delivery");
        assert!(obj.attributes[0].to_ids);
    }

    #[test]
    fn generic_object_with_references() {
        let obj = GenericObjectGenerator::new("file")
            .add_attribute("filename", "malware.exe")
            .add_reference("target-uuid-123", "dropped-by")
            .generate()
            .unwrap();
        assert_eq!(obj.references.len(), 1);
        assert_eq!(
            obj.references[0].referenced_uuid.as_deref(),
            Some("target-uuid-123")
        );
        assert_eq!(
            obj.references[0].relationship_type.as_deref(),
            Some("dropped-by")
        );
    }

    #[test]
    fn generic_object_with_comment_and_distribution() {
        let obj = GenericObjectGenerator::new("file")
            .comment("test object")
            .distribution(1)
            .add_attribute("filename", "test.txt")
            .generate()
            .unwrap();
        assert_eq!(obj.comment.as_deref(), Some("test object"));
        assert_eq!(obj.distribution, Some(1));
    }

    #[test]
    fn generic_object_unknown_type_defaults_to_other() {
        let obj = GenericObjectGenerator::new("custom")
            .add_attribute("custom-field", "value")
            .generate()
            .unwrap();
        // Unknown type should default to "Other" category
        assert_eq!(obj.attributes[0].category, "Other");
        assert!(!obj.attributes[0].to_ids);
    }
}
