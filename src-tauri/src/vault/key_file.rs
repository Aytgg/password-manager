use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::Path,
};

use crate::crypto::key_encryption::ProtectedMasterKey;

pub fn save_protected_master_key(
    path: &Path,
    protected: &ProtectedMasterKey,
) -> Result<(), String> {
    if path.exists() {
        return Err("Master key file already exists".to_string());
    }

    let parent = path
        .parent()
        .ok_or_else(|| "Invalid master key file path".to_string())?;

    fs::create_dir_all(parent).map_err(|error| error.to_string())?;

    let serialized = serde_json::to_vec(protected).map_err(|error| error.to_string())?;

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options.open(path).map_err(|error| error.to_string())?;

    file.write_all(&serialized)
        .map_err(|error| error.to_string())?;

    file.sync_all().map_err(|error| error.to_string())?;

    Ok(())
}

/// Var olan ana anahtar dosyasını yenisiyle değiştirir (ör. ana parola
/// değişikliği). İçerik önce geçici dosyaya yazılıp diske işlenir, sonra tek
/// adımda yerine taşınır; yarıda kalan bir yazma eski dosyayı bozmaz.
pub fn replace_protected_master_key(
    path: &Path,
    protected: &ProtectedMasterKey,
) -> Result<(), String> {
    if !path.is_file() {
        return Err("Master key file does not exist".to_string());
    }

    let temporary_path = path.with_extension(format!("{}.tmp", std::process::id()));
    let _ = fs::remove_file(&temporary_path);

    if let Err(error) = save_protected_master_key(&temporary_path, protected) {
        let _ = fs::remove_file(&temporary_path);
        return Err(error);
    }

    if let Err(error) = fs::rename(&temporary_path, path) {
        let _ = fs::remove_file(&temporary_path);
        return Err(error.to_string());
    }

    Ok(())
}

pub fn load_protected_master_key(path: &Path) -> Result<ProtectedMasterKey, String> {
    let mut file = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|error| error.to_string())?;

    let mut serialized = Vec::new();

    file.read_to_end(&mut serialized)
        .map_err(|error| error.to_string())?;

    serde_json::from_slice(&serialized).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{key_encryption::protect_master_key, master_key::generate_master_key};

    #[test]
    fn protected_master_key_can_be_saved_and_loaded() {
        let directory = tempfile::tempdir().expect("temporary directory should be created");

        let path = directory.path().join("master-key.json");
        let master_key = generate_master_key();

        let protected = protect_master_key(&[1u8; 32], &master_key)
            .expect("master key protection should succeed");

        save_protected_master_key(&path, &protected).expect("protected master key should be saved");

        let loaded =
            load_protected_master_key(&path).expect("protected master key should be loaded");
        assert_eq!(loaded.nonce, protected.nonce);
        assert_eq!(loaded.ciphertext, protected.ciphertext);
        assert_eq!(loaded.kdf_version, protected.kdf_version);
    }

    #[test]
    fn master_key_file_can_be_replaced_with_new_password() {
        use crate::crypto::key_encryption::unlock_master_key;

        let directory = tempfile::tempdir().expect("temporary directory should be created");
        let path = directory.path().join("master-key.json");
        let master_key = generate_master_key();

        let old = protect_master_key(&[2u8; 32], &master_key).unwrap();
        save_protected_master_key(&path, &old).unwrap();

        let new = protect_master_key(&[3u8; 32], &master_key).unwrap();
        replace_protected_master_key(&path, &new).unwrap();

        let loaded = load_protected_master_key(&path).unwrap();

        assert!(unlock_master_key(&[2u8; 32], &loaded).is_err());
        assert_eq!(
            unlock_master_key(&[3u8; 32], &loaded).unwrap().as_ref(),
            master_key.as_ref()
        );

        let leftovers: Vec<_> = std::fs::read_dir(directory.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(leftovers, ["master-key.json"]);
    }

    #[test]
    fn replacing_requires_an_existing_master_key_file() {
        let directory = tempfile::tempdir().expect("temporary directory should be created");
        let path = directory.path().join("master-key.json");
        let protected = protect_master_key(&[4u8; 32], &generate_master_key()).unwrap();

        assert!(replace_protected_master_key(&path, &protected).is_err());
        assert!(!path.exists());
    }

    #[test]
    fn existing_master_key_file_is_not_overwritten() {
        let directory = tempfile::tempdir().expect("temporary directory should be created");

        let path = directory.path().join("master-key.json");
        let master_key = generate_master_key();

        let protected = protect_master_key(&[1u8; 32], &master_key)
            .expect("master key protection should succeed");

        save_protected_master_key(&path, &protected).expect("first save should succeed");

        let result = save_protected_master_key(&path, &protected);

        assert!(result.is_err());
    }
}
