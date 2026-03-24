use thiserror::Error;

/// All errors that can occur when using RustMISP.
#[derive(Debug, Error)]
pub enum MispError {
    /// HTTP request failed.
    #[error("HTTP error: {0}")]
    HttpError(#[from] reqwest::Error),

    /// JSON serialization/deserialization failed.
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),

    /// URL parsing failed.
    #[error("URL parse error: {0}")]
    UrlError(#[from] url::ParseError),

    /// The MISP server returned an error response.
    #[error("MISP API error ({status}): {message}")]
    ApiError { status: u16, message: String },

    /// Authentication failed (invalid API key or insufficient permissions).
    #[error("Authentication error: {0}")]
    AuthError(String),

    /// The requested resource was not found.
    #[error("Not found: {0}")]
    NotFound(String),

    /// Invalid input provided to a method.
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// An entity (event, attribute, etc.) is missing a required field.
    #[error("Missing field: {0}")]
    MissingField(String),

    /// The MISP instance version is not compatible.
    #[error("Version mismatch: {0}")]
    VersionMismatch(String),

    /// I/O error (file operations, etc.).
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// The server returned an unexpected response format.
    #[error("Unexpected response: {0}")]
    UnexpectedResponse(String),

    /// A search query was malformed.
    #[error("Invalid search: {0}")]
    InvalidSearch(String),

    /// An operation timed out.
    #[error("Timeout: {0}")]
    Timeout(String),

    /// TLS/SSL certificate error.
    #[error("TLS error: {0}")]
    TlsError(String),

    /// A feature-gated tool was used without enabling the feature.
    #[error("Feature not enabled: {0}")]
    FeatureNotEnabled(String),
}

/// Convenience type alias for Results using [`MispError`].
pub type MispResult<T> = Result<T, MispError>;
