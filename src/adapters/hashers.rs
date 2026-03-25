//! Password hashing adapters.

use crate::domain::ports::PasswordHasher;

/// Argon2 password hasher.
pub struct Argon2Hasher;

impl Argon2Hasher {
    pub fn new() -> Self {
        Self
    }
}

impl Default for Argon2Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl PasswordHasher for Argon2Hasher {
    fn hash(&self, password: &str) -> Result<String, String> {
        argon2::password_hash::PasswordHash::generate(
            argon2::Algorithm::Argon2id,
            argon2::Params::new(65536, 3, 4, Some(32)).map_err(|e| e.to_string())?,
            password,
        )
        .map(|h| h.to_string())
        .map_err(|e| e.to_string())
    }

    fn verify(&self, password: &str, hash: &str) -> bool {
        argon2::password_hash::PasswordHash::from_encoded(hash)
            .map(|parsed| parsed.verify_password(password).is_ok())
            .unwrap_or(false)
    }
}

/// Bcrypt password hasher.
pub struct BcryptHasher {
    cost: u32,
}

impl BcryptHasher {
    pub fn new(cost: u32) -> Self {
        Self { cost }
    }

    pub fn default_cost() -> Self {
        Self::new(12)
    }
}

impl Default for BcryptHasher {
    fn default() -> Self {
        Self::default_cost()
    }
}

impl PasswordHasher for BcryptHasher {
    fn hash(&self, password: &str) -> Result<String, String> {
        bcrypt::hash(password, self.cost).map_err(|e| e.to_string())
    }

    fn verify(&self, password: &str, hash: &str) -> bool {
        bcrypt::verify(password, hash).unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_argon2_hash_verify() {
        let hasher = Argon2Hasher::new();
        let hash = hasher.hash("password123").unwrap();
        assert!(hasher.verify("password123", &hash));
        assert!(!hasher.verify("wrongpassword", &hash));
    }

    #[test]
    fn test_bcrypt_hash_verify() {
        let hasher = BcryptHasher::new(4);
        let hash = hasher.hash("password123").unwrap();
        assert!(hasher.verify("password123", &hash));
        assert!(!hasher.verify("wrongpassword", &hash));
    }
}
