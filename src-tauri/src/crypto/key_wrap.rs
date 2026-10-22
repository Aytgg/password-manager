use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::Zeroizing;

const KEY_LENGTH: usize = 32;
const NONCE_LENGTH: usize = 12;

const HKDF_INFO: &[u8] = b"password-manager/dek-wrap/v1";

pub struct WrappedKey {
    pub ephemeral_public_key: [u8; 32],
    pub nonce: [u8; NONCE_LENGTH],
    pub ciphertext: Vec<u8>,
}

pub fn generate_identity_keypair() -> (StaticSecret, PublicKey) {
    let private_key = StaticSecret::random();
    let public_key = PublicKey::from(&private_key);

    (private_key, public_key)
}

pub fn wrap_dek(
    dek: &[u8; KEY_LENGTH],
    recipient_public_key: &PublicKey,
) -> Result<WrappedKey, String> {
    let ephemeral_secret = EphemeralSecret::random();
    let ephemeral_public_key = PublicKey::from(&ephemeral_secret);

    let shared_secret = ephemeral_secret.diffie_hellman(recipient_public_key);

    let hkdf = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());

    let mut wrapping_key = Zeroizing::new([0u8; KEY_LENGTH]);

    hkdf.expand(HKDF_INFO, &mut *wrapping_key)
        .map_err(|_| "HKDF expansion failed".to_string())?;

    let cipher = Aes256Gcm::new_from_slice(&*wrapping_key).map_err(|error| error.to_string())?;

    let mut nonce = [0u8; NONCE_LENGTH];
    rand::rng().fill_bytes(&mut nonce);

    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), dek.as_ref())
        .map_err(|_| "DEK wrapping failed".to_string())?;

    Ok(WrappedKey {
        ephemeral_public_key: ephemeral_public_key.to_bytes(),
        nonce,
        ciphertext,
    })
}

pub fn unwrap_dek(
    wrapped: &WrappedKey,
    recipient_private_key: &StaticSecret,
) -> Result<Zeroizing<[u8; KEY_LENGTH]>, String> {
    let ephemeral_public_key = PublicKey::from(wrapped.ephemeral_public_key);

    let shared_secret = recipient_private_key.diffie_hellman(&ephemeral_public_key);

    let hkdf = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());

    let mut wrapping_key = Zeroizing::new([0u8; KEY_LENGTH]);

    hkdf.expand(HKDF_INFO, &mut *wrapping_key)
        .map_err(|_| "HKDF expansion failed".to_string())?;

    let cipher = Aes256Gcm::new_from_slice(&*wrapping_key).map_err(|error| error.to_string())?;

    let dek = cipher
        .decrypt(
            Nonce::from_slice(&wrapped.nonce),
            wrapped.ciphertext.as_ref(),
        )
        .map_err(|_| "DEK unwrapping failed".to_string())?;

    let dek: [u8; KEY_LENGTH] = dek
        .try_into()
        .map_err(|_| "Invalid DEK length".to_string())?;

    Ok(Zeroizing::new(dek))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrapped_dek_can_be_unwrapped_with_correct_private_key() {
        let (private_key, public_key) = generate_identity_keypair();

        let dek = Zeroizing::new([42u8; KEY_LENGTH]);

        let wrapped = wrap_dek(&dek, &public_key).expect("DEK wrapping should succeed");

        let unwrapped = unwrap_dek(&wrapped, &private_key).expect("DEK unwrapping should succeed");

        assert_eq!(dek.as_ref(), unwrapped.as_ref());
    }

    #[test]
    fn wrapped_dek_cannot_be_unwrapped_with_wrong_private_key() {
        let (_, public_key) = generate_identity_keypair();
        let (wrong_private_key, _) = generate_identity_keypair();

        let dek = Zeroizing::new([42u8; KEY_LENGTH]);

        let wrapped = wrap_dek(&dek, &public_key).expect("DEK wrapping should succeed");

        let result = unwrap_dek(&wrapped, &wrong_private_key);

        assert!(result.is_err());
    }

    #[test]
    fn wrapping_same_dek_twice_produces_different_results() {
        let (_, public_key) = generate_identity_keypair();

        let dek = Zeroizing::new([42u8; KEY_LENGTH]);

        let first = wrap_dek(&dek, &public_key).expect("first wrapping should succeed");

        let second = wrap_dek(&dek, &public_key).expect("second wrapping should succeed");

        assert_ne!(first.ephemeral_public_key, second.ephemeral_public_key);

        assert_ne!(first.nonce, second.nonce);

        assert_ne!(first.ciphertext, second.ciphertext);
    }
}
