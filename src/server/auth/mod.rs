//! Authentication helpers for the TDS server.
//!
//! This module provides authentication infrastructure for TDS servers:
//!
//! - [`AuthBuilder`] - Builder pattern for configuring authentication
//! - [`TdsAuthHandler`] - The main authentication handler
//! - [`SqlAuthSource`], [`FedAuthValidator`], [`SspiAcceptor`] - Traits for auth backends
//! - [`LoginInfo`] - Parsed login information from clients
//! - [`AuthError`], [`AuthSuccess`] - Authentication result types

mod builder;
mod env_provider;
mod error;
#[cfg(all(unix, feature = "integrated-auth-gssapi"))]
pub mod gssapi;
mod handler;
mod login_info;
mod traits;

// Re-exports
pub use builder::AuthBuilder;
pub use env_provider::DefaultEnvChangeProvider;
pub use error::{AuthError, AuthResult, AuthSuccess};
pub use handler::TdsAuthHandler;
pub use login_info::LoginInfo;
pub use traits::{
    EnvChangeProvider, FedAuthValidator, SqlAuthSource, SspiAcceptor, SspiSession, SspiStart,
    SspiStep,
};

// Deprecated constants for backwards compatibility
#[deprecated(since = "0.13.0", note = "Use ConnectionMetadata struct instead")]
pub const METADATA_USER: &str = "user";
#[deprecated(since = "0.13.0", note = "Use ConnectionMetadata struct instead")]
pub const METADATA_DATABASE: &str = "database";
#[deprecated(since = "0.13.0", note = "Use ConnectionMetadata struct instead")]
pub const METADATA_APPLICATION: &str = "application";
#[deprecated(since = "0.13.0", note = "Use ConnectionMetadata struct instead")]
pub const METADATA_SERVER: &str = "server";
