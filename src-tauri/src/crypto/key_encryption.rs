use serde::{Deserialize, Serialize};

use super::{
    aes::{self, EncryptedData},
    kdf,
    master_key::MasterKey,
};

#[derive(Serialize, Deserialize)]
pub struct ProtectedMasterKey {
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; 12],
    pub kdf_version: u8,
}

/// Ana anahtarı paroladan türetilmiş `kek` ile şifreler.
pub fn protect_master_key(
    kek: &[u8; 32],
    master_key: &MasterKey,
) -> Result<ProtectedMasterKey, String> {
    let encrypted = aes::encrypt(master_key.as_ref(), kek)?;

    Ok(ProtectedMasterKey {
        ciphertext: encrypted.ciphertext,
        nonce: encrypted.nonce,
        kdf_version: kdf::kdf_version(),
    })
}

pub fn unlock_master_key(
    kek: &[u8; 32],
    protected: &ProtectedMasterKey,
) -> Result<MasterKey, String> {
    // Desteklenmeyen KDF sürümleriyle işlem yapma.
    if protected.kdf_version != kdf::kdf_version() {
        return Err("Unsupported key derivation version".to_string());
    }

    let encrypted = EncryptedData {
        ciphertext: protected.ciphertext.clone(),
        nonce: protected.nonce,
    };

    let plaintext = aes::decrypt(&encrypted, kek)?;

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
    fn master_key_can_be_unlocked_with_correct_kek() {
        let kek = [7u8; 32];
        let master_key = generate_master_key();

        let protected = protect_master_key(&kek, &master_key)
            .expect("master key protection should succeed");

        let unlocked = unlock_master_key(&kek, &protected).expect("master key should be unlocked");

        assert_eq!(master_key.as_ref(), unlocked.as_ref());
    }

    #[test]
    fn master_key_cannot_be_unlocked_with_wrong_kek() {
        let master_key = generate_master_key();

        let protected = protect_master_key(&[7u8; 32], &master_key)
            .expect("master key protection should succeed");

        assert!(unlock_master_key(&[8u8; 32], &protected).is_err());
    }

    #[test]
    fn each_master_key_protection_uses_a_new_nonce() {
        let kek = [7u8; 32];
        let master_key = generate_master_key();

        let first = protect_master_key(&kek, &master_key).unwrap();
        let second = protect_master_key(&kek, &master_key).unwrap();

        assert_ne!(first.nonce, second.nonce);
        assert_ne!(first.ciphertext, second.ciphertext);
    }

    #[test]
    fn unsupported_kdf_version_is_rejected() {
        let kek = [7u8; 32];
        let mut protected = protect_master_key(&kek, &generate_master_key()).unwrap();

        protected.kdf_version = 255;

        assert!(unlock_master_key(&kek, &protected).is_err());
    }
}
