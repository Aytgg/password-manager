use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
    Aes256Gcm, Nonce,
};
use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::crypto::master_key::MasterKey;

const OWNER_BINDING_VERSION: u8 = 1;
const OWNER_BINDING_AAD: &[u8] = b"password-manager-vault-owner-binding:v1";
const NONCE_LENGTH: usize = 12;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OwnerBindingFile {
    version: u8,
    nonce: String,
    ciphertext: String,
}

fn make_cipher(master_key: &MasterKey) -> Result<Aes256Gcm, String> {
    Aes256Gcm::new_from_slice(&master_key[..])
        .map_err(|_| "Kasa sahibi doğrulama anahtarı hazırlanamadı.".to_string())
}

pub fn save_owner_binding(
    path: &Path,
    master_key: &MasterKey,
    clerk_user_id: &str,
) -> Result<(), String> {
    let clerk_user_id = clerk_user_id.trim();

    if clerk_user_id.is_empty() {
        return Err("Clerk kullanıcı kimliği boş olamaz.".to_string());
    }

    if path.exists() {
        return Err("Kasa sahibi doğrulama dosyası zaten mevcut.".to_string());
    }

    let cipher = make_cipher(master_key)?;
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: clerk_user_id.as_bytes(),
                aad: OWNER_BINDING_AAD,
            },
        )
        .map_err(|_| "Kasa sahibi doğrulama bilgisi şifrelenemedi.".to_string())?;

    let envelope = OwnerBindingFile {
        version: OWNER_BINDING_VERSION,
        nonce: hex::encode(nonce.as_slice()),
        ciphertext: hex::encode(ciphertext),
    };

    let serialized = serde_json::to_vec(&envelope)
        .map_err(|error| format!("Kasa sahibi bilgisi serileştirilemedi: {error}"))?;

    let temporary_path =
        path.with_extension(format!("{}.tmp", std::process::id()));

    if temporary_path.exists() {
        return Err("Geçici kasa sahibi dosyası zaten mevcut.".to_string());
    }

    let write_result = std::fs::write(&temporary_path, serialized)
        .map_err(|error| format!("Kasa sahibi bilgisi yazılamadı: {error}"));

    if let Err(error) = write_result {
        let _ = std::fs::remove_file(&temporary_path);
        return Err(error);
    }

    if let Err(error) = std::fs::rename(&temporary_path, path) {
        let _ = std::fs::remove_file(&temporary_path);
        return Err(format!("Kasa sahibi dosyası kaydedilemedi: {error}"));
    }

    Ok(())
}

pub fn verify_owner_binding(
    path: &Path,
    master_key: &MasterKey,
    authenticated_clerk_user_id: &str,
) -> Result<(), String> {
    let authenticated_clerk_user_id = authenticated_clerk_user_id.trim();

    if authenticated_clerk_user_id.is_empty() {
        return Err("Clerk kullanıcı kimliği boş olamaz.".to_string());
    }

    let serialized = std::fs::read(path).map_err(|error| {
        format!(
            "Kasa sahibi doğrulama dosyası okunamadı. \
            Bu kasa eski bir sürümde oluşturulmuş olabilir: {error}"
        )
    })?;

    let envelope: OwnerBindingFile = serde_json::from_slice(&serialized)
        .map_err(|_| "Kasa sahibi doğrulama dosyası geçersiz.".to_string())?;

    if envelope.version != OWNER_BINDING_VERSION {
        return Err("Kasa sahibi doğrulama dosyası sürümü desteklenmiyor.".to_string());
    }

    let nonce_bytes = hex::decode(&envelope.nonce)
        .map_err(|_| "Kasa sahibi nonce değeri geçersiz.".to_string())?;

    if nonce_bytes.len() != NONCE_LENGTH {
        return Err("Kasa sahibi nonce uzunluğu geçersiz.".to_string());
    }

    let ciphertext = hex::decode(&envelope.ciphertext)
        .map_err(|_| "Kasa sahibi şifreli verisi geçersiz.".to_string())?;

    let nonce = Nonce::from_slice(&nonce_bytes);
    let cipher = make_cipher(master_key)?;

    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: &ciphertext,
                aad: OWNER_BINDING_AAD,
            },
        )
        .map_err(|_| "Kasa sahibi bilgisi doğrulanamadı.".to_string())?;

    if plaintext.as_slice() != authenticated_clerk_user_id.as_bytes() {
        return Err(
            "Bu yerel kasa farklı bir Clerk hesabına ait.".to_string(),
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use zeroize::Zeroizing;

    #[test]
    fn matching_user_can_verify_binding() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("vault-owner.json");
        let key = Zeroizing::new([41u8; 32]);

        save_owner_binding(&path, &key, "user-a").unwrap();

        assert!(verify_owner_binding(&path, &key, "user-a").is_ok());
    }

    #[test]
    fn different_user_cannot_verify_binding() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("vault-owner.json");
        let key = Zeroizing::new([41u8; 32]);

        save_owner_binding(&path, &key, "user-a").unwrap();

        assert!(verify_owner_binding(&path, &key, "user-b").is_err());
    }

    #[test]
    fn wrong_master_key_is_rejected() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("vault-owner.json");
        let original_key = Zeroizing::new([41u8; 32]);
        let wrong_key = Zeroizing::new([42u8; 32]);

        save_owner_binding(&path, &original_key, "user-a").unwrap();

        assert!(verify_owner_binding(&path, &wrong_key, "user-a").is_err());
    }

    #[test]
    fn existing_binding_cannot_be_overwritten() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("vault-owner.json");
        let key = Zeroizing::new([41u8; 32]);

        save_owner_binding(&path, &key, "user-a").unwrap();

        assert!(save_owner_binding(&path, &key, "user-b").is_err());
        assert!(verify_owner_binding(&path, &key, "user-a").is_ok());
    }

    #[test]
    fn missing_binding_is_rejected() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("missing-owner.json");
        let key = Zeroizing::new([41u8; 32]);

        assert!(verify_owner_binding(&path, &key, "user-a").is_err());
    }
}
