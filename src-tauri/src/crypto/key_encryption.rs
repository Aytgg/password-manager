use serde::{Deserialize, Serialize};

use super::{
    aes::{self, EncryptedData},
    kdf::{self, KeyPurpose},
    master_key::MasterKey,
};

#[derive(Serialize, Deserialize)]
pub struct ProtectedMasterKey {
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; 12],
    pub salt: [u8; 16],
    pub kdf_version: u8,
}

pub fn protect_master_key(
    password: &[u8],
    master_key: &MasterKey,
) -> Result<ProtectedMasterKey, String> {
    let salt = kdf::generate_salt();

    let derived_key = kdf::derive_key(password, salt, KeyPurpose::KeyEncryption)?;

    let encrypted = aes::encrypt(master_key.as_ref(), &derived_key.key)?;

    Ok(ProtectedMasterKey {
        ciphertext: encrypted.ciphertext,
        nonce: encrypted.nonce,
        salt: derived_key.salt,
        kdf_version: kdf::kdf_version(),
    })
}

pub fn unlock_master_key(
    password: &[u8],
    protected: &ProtectedMasterKey,
) -> Result<MasterKey, String> {
    // Desteklenmeyen KDF sürümleriyle işlem yapma.
    if protected.kdf_version != kdf::kdf_version() {
        return Err("Unsupported key derivation version".to_string());
    }

    let derived_key = kdf::derive_key(password, protected.salt, KeyPurpose::KeyEncryption)?;

    let encrypted = EncryptedData {
        ciphertext: protected.ciphertext.clone(),
        nonce: protected.nonce,
    };

    let plaintext = aes::decrypt(&encrypted, &derived_key.key)?;

    let master_key: [u8; 32] = plaintext
        .as_slice()
        .try_into()
        .map_err(|_| "Invalid master key length".to_string())?;

    Ok(zeroize::Zeroizing::new(master_key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::master_key::generate_master_key;

    #[test]
    fn master_key_can_be_unlocked_with_correct_password() {
        let password = b"correct-password";
        let master_key = generate_master_key();

        let protected = protect_master_key(password, &master_key)
            .expect("master key protection should succeed");

        let unlocked =
            unlock_master_key(password, &protected).expect("master key should be unlocked");

        assert_eq!(master_key.as_ref(), unlocked.as_ref());
    }

    #[test]
    fn master_key_cannot_be_unlocked_with_wrong_password() {
        let master_key = generate_master_key();

        let protected = protect_master_key(b"correct-password", &master_key)
            .expect("master key protection should succeed");

        let result = unlock_master_key(b"wrong-password", &protected);

        assert!(result.is_err());
    }

    #[test]
    fn each_master_key_protection_uses_a_new_salt_and_nonce() {
        let password = b"same-password";
        let master_key = generate_master_key();

        let first =
            protect_master_key(password, &master_key).expect("first protection should succeed");

        let second =
            protect_master_key(password, &master_key).expect("second protection should succeed");

        assert_ne!(first.salt, second.salt);
        assert_ne!(first.nonce, second.nonce);
        assert_ne!(first.ciphertext, second.ciphertext);
    }

    #[test]
    fn unsupported_kdf_version_is_rejected() {
        let master_key = generate_master_key();

        let mut protected = protect_master_key(b"correct-password", &master_key)
            .expect("master key protection should succeed");

        protected.kdf_version = 255;

        let result = unlock_master_key(b"correct-password", &protected);

        assert!(result.is_err());
    }
}
