//! Authentication and authorization framework.
//!
//! # Architecture
//!
//! authkit follows hexagonal architecture:
//!
//! - **Domain**: Pure business logic (identity, auth, policy)
//! - **Application**: Use cases and auth services
//! - **Adapters**: JWT, OAuth2, storage, hashers
//! - **Infrastructure**: Cross-cutting concerns (error handling, logging)
//!
//! # Quick Start
//!
//! ```
//! use authkit::{Authenticator, UserId};
//!
//! let auth = Authenticator::new(secret_key)?;
//! let token = auth.generate_token(UserId::new(), &["admin"])?;
//! ```

pub mod domain;
pub mod application;
pub mod adapters;
pub mod infrastructure;

// Re-exports
pub use domain::{UserId, Role, Permission, Claims};
pub use domain::errors::AuthError;
pub use application::services::Authenticator;
pub use infrastructure::error::AuthKitError;

/// Framework version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
