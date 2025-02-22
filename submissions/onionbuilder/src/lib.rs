pub mod types;
pub mod crypto;
pub mod builder;
pub mod constants;

// Re-export main types for easier access
pub use types::{OnionPayload, Hop, HopKeys};
pub use crypto::SphinxCrypto;
pub use builder::OnionPacketBuilder;
pub use constants::*;

use std::fmt;

// Custom error type for the library
#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Json(serde_json::Error),
    Hex(hex::FromHexError),
    Crypto(String),
    InvalidInput(String),
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            Error::Json(e) => Some(e),
            Error::Hex(e) => Some(e),
            _ => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "IO error: {}", e),
            Error::Json(e) => write!(f, "JSON error: {}", e),
            Error::Hex(e) => write!(f, "Hex decode error: {}", e),
            Error::Crypto(e) => write!(f, "Cryptographic error: {}", e),
            Error::InvalidInput(e) => write!(f, "Invalid input: {}", e),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::Io(err)
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Error::Json(err)
    }
}

impl From<hex::FromHexError> for Error {
    fn from(err: hex::FromHexError) -> Self {
        Error::Hex(err)
    }
}

pub type Result<T> = std::result::Result<T, Error>;