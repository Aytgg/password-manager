use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use rand::RngCore;

use zeroize::Zeroizing;

const KEY_LENGTH: usize = 32;
const NONCE_LENGTH: usize = 12;

pub struct EncryptedData {
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; NONCE_LENGTH],
}

pub fn encrypt(plaintext: &[u8], key: &[u8; KEY_LENGTH]) -> Result<EncryptedData, String> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|error| error.to_string())?;

    let mut nonce = [0u8; NONCE_LENGTH];
    rand::rng().fill_bytes(&mut nonce);

    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|_| "Encryption failed".to_string())?;

    Ok(EncryptedData { ciphertext, nonce })
}

pub fn decrypt(
    encrypted: &EncryptedData,
    key: &[u8; KEY_LENGTH],
) -> Result<Zeroizing<Vec<u8>>, String> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|error| error.to_string())?;

    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&encrypted.nonce),
            encrypted.ciphertext.as_ref(),
        )
        .map_err(|_| "Decryption failed".to_string())?;

    Ok(Zeroizing::new(plaintext))
}
