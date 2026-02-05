//! Slipstream DNS tunnel client library.
//!
//! This module provides the core functionality for the slipstream DNS tunnel client,
//! including Android JNI bindings for mobile deployment.

pub mod dns;
pub mod error;
pub mod pacing;
pub mod pinning;
pub mod runtime;
pub mod streams;

#[cfg(target_os = "android")]
pub mod android;

// Re-export key types for library users
pub use error::ClientError;
pub use runtime::run_client;
