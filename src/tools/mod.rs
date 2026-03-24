//! Tools for generating and manipulating MISP objects and attributes.

pub mod generic_object;

#[cfg(feature = "tools-file")]
pub mod file_object;

#[cfg(feature = "tools-csv")]
pub mod csv_loader;

#[cfg(feature = "tools-openioc")]
pub mod openioc;

#[cfg(feature = "tools-feed")]
pub mod feed_generator;

use crate::error::MispResult;
use crate::models::object::MispObject;

/// Trait for MISP object generators.
///
/// Implementations produce a [`MispObject`] populated with attributes and
/// references according to a specific template or data source.
pub trait MispObjectGenerator {
    /// Generate a fully-populated [`MispObject`].
    fn generate(&self) -> MispResult<MispObject>;

    /// Return the template name for this object generator.
    fn template_name(&self) -> &str;
}
