//! File object generator — reads a file and computes hashes.

use std::fs;
use std::path::{Path, PathBuf};

use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};

use crate::error::{MispError, MispResult};
use crate::models::attribute::MispAttribute;
use crate::models::object::MispObject;

use super::MispObjectGenerator;

/// Generates a MISP "file" object from a file on disk, computing MD5, SHA-1,
/// SHA-256, and SHA-512 hashes.
///
/// # Example
/// ```no_run
/// use rustmisp::tools::file_object::FileObject;
/// use rustmisp::tools::MispObjectGenerator;
///
/// let fo = FileObject::new("test.bin").unwrap();
/// let obj = fo.generate().unwrap();
/// assert_eq!(obj.name, "file");
/// ```
#[derive(Debug, Clone)]
pub struct FileObject {
    path: PathBuf,
    filename: Option<String>,
    data: Vec<u8>,
}

impl FileObject {
    /// Create a `FileObject` from a path, reading the file contents.
    pub fn new(path: impl AsRef<Path>) -> MispResult<Self> {
        let path = path.as_ref().to_path_buf();
        let data = fs::read(&path).map_err(|e| {
            MispError::InvalidInput(format!("Failed to read file {}: {}", path.display(), e))
        })?;
        Ok(Self {
            path,
            filename: None,
            data,
        })
    }

    /// Create a `FileObject` from raw bytes and a name.
    pub fn from_bytes(filename: impl Into<String>, data: Vec<u8>) -> Self {
        Self {
            path: PathBuf::new(),
            filename: Some(filename.into()),
            data,
        }
    }

    /// Override the filename used in the generated object.
    pub fn set_filename(mut self, name: impl Into<String>) -> Self {
        self.filename = Some(name.into());
        self
    }

    fn resolved_filename(&self) -> String {
        self.filename.clone().unwrap_or_else(|| {
            self.path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| "unknown".to_string())
        })
    }

    fn make_attr(&self, object_relation: &str, attr_type: &str, value: String) -> MispAttribute {
        let mut attr = MispAttribute::new(attr_type, "Payload delivery", &value);
        attr.object_relation = Some(object_relation.to_string());
        attr.to_ids = true;
        attr
    }
}

impl MispObjectGenerator for FileObject {
    fn template_name(&self) -> &str {
        "file"
    }

    fn generate(&self) -> MispResult<MispObject> {
        let mut obj = MispObject::new("file");
        obj.meta_category = Some("file".to_string());

        // Filename
        let filename = self.resolved_filename();
        let mut fname_attr = MispAttribute::new("filename", "Payload delivery", &filename);
        fname_attr.object_relation = Some("filename".to_string());
        fname_attr.to_ids = true;
        obj.add_attribute(fname_attr);

        // Size
        let mut size_attr =
            MispAttribute::new("size-in-bytes", "Other", self.data.len().to_string());
        size_attr.object_relation = Some("size-in-bytes".to_string());
        size_attr.to_ids = false;
        obj.add_attribute(size_attr);

        // MD5
        let md5_hash = format!("{:x}", Md5::digest(&self.data));
        obj.add_attribute(self.make_attr("md5", "md5", md5_hash));

        // SHA-1
        let sha1_hash = format!("{:x}", Sha1::digest(&self.data));
        obj.add_attribute(self.make_attr("sha1", "sha1", sha1_hash));

        // SHA-256
        let sha256_hash = format!("{:x}", Sha256::digest(&self.data));
        obj.add_attribute(self.make_attr("sha256", "sha256", sha256_hash));

        // SHA-512
        let sha512_hash = format!("{:x}", Sha512::digest(&self.data));
        obj.add_attribute(self.make_attr("sha512", "sha512", sha512_hash));

        Ok(obj)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_object_from_bytes() {
        let data = b"hello world".to_vec();
        let fo = FileObject::from_bytes("test.txt", data);
        let obj = fo.generate().unwrap();
        assert_eq!(obj.name, "file");
        assert_eq!(obj.meta_category.as_deref(), Some("file"));
        assert_eq!(obj.attributes.len(), 6);

        // Check filename
        assert_eq!(obj.attributes[0].value, "test.txt");
        assert_eq!(
            obj.attributes[0].object_relation.as_deref(),
            Some("filename")
        );

        // Check size
        assert_eq!(obj.attributes[1].value, "11");
        assert_eq!(
            obj.attributes[1].object_relation.as_deref(),
            Some("size-in-bytes")
        );

        // Check MD5 of "hello world"
        assert_eq!(obj.attributes[2].value, "5eb63bbbe01eeed093cb22bb8f5acdc3");
        assert_eq!(obj.attributes[2].object_relation.as_deref(), Some("md5"));

        // Check SHA1
        assert_eq!(
            obj.attributes[3].value,
            "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed"
        );

        // Check SHA256
        assert_eq!(
            obj.attributes[4].value,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn file_object_custom_filename() {
        let fo =
            FileObject::from_bytes("original.txt", b"data".to_vec()).set_filename("custom.bin");
        let obj = fo.generate().unwrap();
        assert_eq!(obj.attributes[0].value, "custom.bin");
    }

    #[test]
    fn file_object_template_name() {
        let fo = FileObject::from_bytes("test.txt", vec![]);
        assert_eq!(fo.template_name(), "file");
    }
}
