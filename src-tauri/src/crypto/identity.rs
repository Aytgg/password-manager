use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

pub struct IdentityKeyPair {
    private_key: Zeroizing<[u8; 32]>,
    public_key: PublicKey,
}

impl IdentityKeyPair {
    pub fn generate() -> Self {
        let private_key = StaticSecret::random();
        Self::from_private_key(private_key.to_bytes())
    }

    pub fn from_private_key(bytes: [u8; 32]) -> Self {
        let private_key = StaticSecret::from(bytes);
        let public_key = PublicKey::from(&private_key);

        Self {
            private_key: Zeroizing::new(bytes),
            public_key,
        }
    }

    pub fn public_key(&self) -> PublicKey {
        self.public_key
    }

    pub fn private_key(&self) -> &[u8; 32] {
        &self.private_key
    }

    pub fn private_secret(&self) -> StaticSecret {
        StaticSecret::from(*self.private_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_identity_key_pair() {
        let identity = IdentityKeyPair::generate();

        assert_ne!(identity.public_key().to_bytes(), [0u8; 32]);
        assert_ne!(identity.private_key(), &[0u8; 32]);
    }

    #[test]
    fn generates_different_keys_each_time() {
        let first = IdentityKeyPair::generate();
        let second = IdentityKeyPair::generate();

        assert_ne!(
            first.public_key().to_bytes(),
            second.public_key().to_bytes()
        );
        assert_ne!(first.private_key(), second.private_key());
    }

    #[test]
    fn public_key_is_derived_from_private_key() {
        let identity = IdentityKeyPair::generate();
        let private_key = StaticSecret::from(*identity.private_key());
        let expected_public_key = PublicKey::from(&private_key);

        assert_eq!(identity.public_key(), expected_public_key);
    }

    #[test]
    fn restores_identity_from_private_key() {
        let original = IdentityKeyPair::generate();
        let restored = IdentityKeyPair::from_private_key(*original.private_key());

        assert_eq!(original.public_key(), restored.public_key());
        assert_eq!(original.private_key(), restored.private_key());
    }
}
