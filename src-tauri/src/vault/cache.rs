//! Çevrimdışı erişim için yerel kayıt önbelleği.
//!
//! İçerik arayüzün tuttuğu biçimdedir (sunucudan gelen şifreli kayıtlar ve
//! henüz gönderilmemiş yeni kayıtlar); Rust onu yorumlamaz, yalnızca
//! şifreleyip saklar. Kayıtların kendisi zaten şifreli olduğu için dosya iki
//! katmanlı korunur: kasa anahtarından türetilen önbellek anahtarı ve her
//! kaydın kendi DEK'i.

use std::{fs, path::Path};

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::crypto::{master_key::MasterKey, password_encryption};

const CACHE_VERSION: u8 = 1;
const CACHE_KEY_INFO: &[u8] = b"password-manager/items-cache-key/v1";
const MAX_CACHE_BYTES: usize = 32 * 1024 * 1024;

pub type CacheKey = Zeroizing<[u8; 32]>;

#[derive(Serialize, Deserialize)]
struct CacheFile {
    version: u8,
    nonce: String,
    ciphertext: String,
}

pub fn derive_cache_key(master_key: &MasterKey) -> Result<CacheKey, String> {
    let hkdf = Hkdf::<Sha256>::from_prk(&master_key[..])
        .map_err(|_| "Önbellek anahtarı türetilemedi.".to_string())?;

    let mut key = Zeroizing::new([0u8; 32]);
    hkdf.expand(CACHE_KEY_INFO, &mut *key)
        .map_err(|_| "Önbellek anahtarı türetilemedi.".to_string())?;

    Ok(key)
}

// Önbellek kullanıcıya bağlanır; başka bir hesabın dosyası buraya
// kopyalansa bile açılmaz.
fn aad(user_id: &str) -> Vec<u8> {
    format!("password-manager/items-cache/v{CACHE_VERSION}:{user_id}").into_bytes()
}

pub fn save_cache(
    path: &Path,
    key: &CacheKey,
    user_id: &str,
    content: &serde_json::Value,
) -> Result<(), String> {
    let plaintext = Zeroizing::new(serde_json::to_vec(content).map_err(|error| error.to_string())?);

    if plaintext.len() > MAX_CACHE_BYTES {
        return Err("Yerel önbellek çok büyük.".to_string());
    }

    let (ciphertext, nonce) = password_encryption::encrypt_password(&plaintext, key, &aad(user_id))?;

    let file = serde_json::to_vec(&CacheFile {
        version: CACHE_VERSION,
        nonce: BASE64.encode(nonce),
        ciphertext: BASE64.encode(ciphertext),
    })
    .map_err(|error| error.to_string())?;

    // Yarıda kalan bir yazma eski önbelleği bozmasın.
    let temporary = path.with_extension(format!("{}.tmp", std::process::id()));

    if let Err(error) = fs::write(&temporary, file).and_then(|()| fs::rename(&temporary, path)) {
        let _ = fs::remove_file(&temporary);
        return Err(format!("Yerel önbellek yazılamadı: {error}"));
    }

    Ok(())
}

/// Önbelleği okur. Dosya yoksa `None`; bozuk ya da başka hesaba aitse hata.
pub fn load_cache(
    path: &Path,
    key: &CacheKey,
    user_id: &str,
) -> Result<Option<serde_json::Value>, String> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("Yerel önbellek okunamadı: {error}")),
    };

    let file: CacheFile =
        serde_json::from_slice(&bytes).map_err(|_| "Yerel önbellek dosyası geçersiz.".to_string())?;

    if file.version != CACHE_VERSION {
        return Ok(None);
    }

    let nonce: [u8; 12] = BASE64
        .decode(&file.nonce)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| "Yerel önbellek dosyası geçersiz.".to_string())?;
    let ciphertext = BASE64
        .decode(&file.ciphertext)
        .map_err(|_| "Yerel önbellek dosyası geçersiz.".to_string())?;

    let plaintext = password_encryption::decrypt_password(&ciphertext, &nonce, key, &aad(user_id))
        .map_err(|_| "Yerel önbellek bu hesabın anahtarıyla açılamadı.".to_string())?;

    serde_json::from_slice(&plaintext)
        .map(Some)
        .map_err(|_| "Yerel önbellek içeriği okunamadı.".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn cache_round_trips_and_is_bound_to_key_and_user() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("items-cache.json");
        let key = derive_cache_key(&Zeroizing::new([1u8; 32])).unwrap();
        let content = serde_json::json!({ "items": [{ "itemId": "item-1" }] });

        assert_eq!(load_cache(&path, &key, "u1").unwrap(), None);

        save_cache(&path, &key, "u1", &content).unwrap();
        assert_eq!(load_cache(&path, &key, "u1").unwrap(), Some(content));

        let other_key = derive_cache_key(&Zeroizing::new([2u8; 32])).unwrap();
        assert!(load_cache(&path, &other_key, "u1").is_err());
        assert!(load_cache(&path, &key, "u2").is_err());

        let leftovers: Vec<_> = fs::read_dir(directory.path()).unwrap().collect();
        assert_eq!(leftovers.len(), 1);
    }
}
