//! Slipstream DNS tunnel client library.
//!
//! This crate provides the core functionality for running a slipstream client
//! that tunnels TCP traffic through DNS queries.

mod dns;
mod error;
mod pacing;
mod pinning;
pub mod runtime;
mod streams;

// Note: android module is always compiled for the cdylib target
// The cfg attribute is removed to ensure JNI symbols are exported
#[cfg(any(target_os = "android", target_os = "linux"))]
pub mod android;

pub use error::ClientError;
pub use runtime::run_client;
