//! Domain layer - pure authentication and authorization logic.

pub mod identity;
pub mod auth;
pub mod policy;
pub mod session;
pub mod ports;
pub mod errors;

// Re-exports
pub use identity::{UserId, User, Role, Permission};
pub use auth::{Authenticator, AuthMethod};
pub use policy::{Policy, PolicyEngine, PolicyEffect};
pub use session::{Session, SessionId};
pub use errors::AuthError;
