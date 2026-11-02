//! Yerel kasanın hangi hesaba ait olduğunu ana anahtarla şifreli olarak
//! saklar. Kasa çevrimdışı açılabildiği için sunucudaki kullanıcı kimliği
//! (yeni kayıtların sahibi ve AAD'si) buradan okunur.

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
    Aes256Gcm, Nonce,
};
use serde::{Deserialize, Serialize};
use std::path::Path;
use zeroize::Zeroizing;

use crate::crypto::master_key::MasterKey;

const OWNER_BINDING_VERSION: u8 = 2;
const OWNER_BINDING_AAD: &[u8] = b"password-manager-vault-owner-binding:v2";
const NONCE_LENGTH: usize = 12;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OwnerBindingFile {
    version: u8,
    nonce: String,
    ciphertext: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultOwner {
    pub email: String,
    pub user_id: String,
}

fn make_cipher(master_key: &MasterKey) -> Result<Aes256Gcm, String> {
    Aes256Gcm::new_from_slice(&master_key[..])
        .map_err(|_| "Kasa sahibi doğrulama anahtarı hazırlanamadı.".to_string())
}

pub fn save_owner_binding(
    path: &Path,
    master_key: &MasterKey,
    owner: &VaultOwner,
) -> Result<(), String> {
    if owner.email.trim().is_empty() || owner.user_id.trim().is_empty() {
        return Err("Kasa sahibi bilgisi eksik.".to_string());
    }

    if path.exists() {
        return Err("Kasa sahibi doğrulama dosyası zaten mevcut.".to_string());
    }

    let plaintext = Zeroizing::new(
        serde_json::to_vec(owner)
            .map_err(|error| format!("Kasa sahibi bilgisi serileştirilemedi: {error}"))?,
    );

    let cipher = make_cipher(master_key)?;
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: &plaintext,
                aad: OWNER_BINDING_AAD,
            },
        )
        .map_err(|_| "Kasa sahibi doğrulama bilgisi şifrelenemedi.".to_string())?;

    let envelope = OwnerBindingFile {
        version: OWNER_BINDING_VERSION,
        nonce: hex::encode(nonce),
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

/// Kasanın sahibini çözer ve beklenen e-postayla eşleştiğini doğrular.
pub fn load_owner_binding(
    path: &Path,
    master_key: &MasterKey,
    expected_email: &str,
) -> Result<VaultOwner, String> {
    let serialized = std::fs::read(path)
        .map_err(|error| format!("Kasa sahibi doğrulama dosyası okunamadı: {error}"))?;

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

    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &ciphertext,
                    aad: OWNER_BINDING_AAD,
                },
            )
            .map_err(|_| "Kasa sahibi bilgisi doğrulanamadı.".to_string())?,
    );

    let owner: VaultOwner = serde_json::from_slice(&plaintext)
        .map_err(|_| "Kasa sahibi bilgisi geçersiz.".to_string())?;

    if owner.email != expected_email.trim() {
        return Err("Bu yerel kasa farklı bir hesaba ait.".to_string());
    }

    Ok(owner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn owner(email: &str) -> VaultOwner {
        VaultOwner {
            email: email.to_string(),
            user_id: format!("id-{email}"),
        }
    }

    #[test]
    fn matching_email_loads_the_owner() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("vault-owner.json");
        let key = Zeroizing::new([41u8; 32]);

        save_owner_binding(&path, &key, &owner("a@x.com")).unwrap();

        assert_eq!(load_owner_binding(&path, &key, "a@x.com").unwrap(), owner("a@x.com"));
    }

    #[test]
    fn different_email_is_rejected() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("vault-owner.json");
        let key = Zeroizing::new([41u8; 32]);

        save_owner_binding(&path, &key, &owner("a@x.com")).unwrap();

        assert!(load_owner_binding(&path, &key, "b@x.com").is_err());
    }

    #[test]
    fn wrong_master_key_is_rejected() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("vault-owner.json");

        save_owner_binding(&path, &Zeroizing::new([41u8; 32]), &owner("a@x.com")).unwrap();

        assert!(load_owner_binding(&path, &Zeroizing::new([42u8; 32]), "a@x.com").is_err());
    }

    #[test]
    fn existing_binding_cannot_be_overwritten() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("vault-owner.json");
        let key = Zeroizing::new([41u8; 32]);

        save_owner_binding(&path, &key, &owner("a@x.com")).unwrap();

        assert!(save_owner_binding(&path, &key, &owner("b@x.com")).is_err());
        assert!(load_owner_binding(&path, &key, "a@x.com").is_ok());
    }

    #[test]
    fn missing_binding_is_rejected() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("missing-owner.json");
        let key = Zeroizing::new([41u8; 32]);

        assert!(load_owner_binding(&path, &key, "a@x.com").is_err());
    }
}
