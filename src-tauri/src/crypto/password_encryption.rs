use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use rand::RngCore;
use zeroize::Zeroizing;

const DEK_LENGTH: usize = 32;
const NONCE_LENGTH: usize = 12;

pub fn generate_dek() -> Zeroizing<[u8; DEK_LENGTH]> {
    let mut dek = Zeroizing::new([0u8; DEK_LENGTH]);

    rand::rng().fill_bytes(&mut *dek);

    dek
}

pub fn encrypt_password(
    password: &[u8],
    dek: &[u8; DEK_LENGTH],
    aad: &[u8],
) -> Result<(Vec<u8>, [u8; NONCE_LENGTH]), String> {
    let cipher = Aes256Gcm::new_from_slice(dek).map_err(|error| error.to_string())?;

    let mut nonce = [0u8; NONCE_LENGTH];
    rand::rng().fill_bytes(&mut nonce);

    let payload = Payload { msg: password, aad };

    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), payload)
        .map_err(|_| "Password encryption failed".to_string())?;

    Ok((ciphertext, nonce))
}

pub fn decrypt_password(
    ciphertext: &[u8],
    nonce: &[u8; NONCE_LENGTH],
    dek: &[u8; DEK_LENGTH],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, String> {
    let cipher = Aes256Gcm::new_from_slice(dek).map_err(|error| error.to_string())?;

    let payload = Payload {
        msg: ciphertext,
        aad,
    };

    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce), payload)
        .map_err(|_| "Password decryption failed".to_string())?;

    Ok(Zeroizing::new(plaintext))
}
