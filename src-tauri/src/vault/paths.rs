use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

const VAULTS_DIR_NAME: &str = "vaults";
const USER_DIR_DOMAIN: &[u8] = b"password-manager/vault-dir/v2:";

/// Bir yerel kasanın diskteki dosyaları.
///
/// Her hesap (e-posta) `app_data_dir/vaults/<hash>/` altında kendi kasasına
/// sahiptir. Klasör adı e-postanın hash'idir; böylece e-posta
/// doğrudan dosya sistemine yansımaz ve yol karakterleri sorun çıkarmaz.
pub struct VaultPaths {
    pub dir: PathBuf,
    pub master_key: PathBuf,
    pub owner_binding: PathBuf,
    pub stronghold: PathBuf,
    pub owner_binding_temp: PathBuf,
    /// Çevrimdışı erişim için sunucudaki kayıtların şifreli kopyası.
    pub items_cache: PathBuf,
}

impl VaultPaths {
    fn in_dir(dir: PathBuf) -> Self {
        let owner_binding = dir.join("vault-owner.json");
        let owner_binding_temp =
            owner_binding.with_extension(format!("{}.tmp", std::process::id()));

        Self {
            master_key: dir.join("master-key.json"),
            stronghold: dir.join("vault.hold"),
            items_cache: dir.join("items-cache.json"),
            owner_binding,
            owner_binding_temp,
            dir,
        }
    }

    pub fn for_email(app_data_dir: &Path, email: &str) -> Result<Self, String> {
        let email = crate::crypto::kdf::normalize_email(email);

        if email.is_empty() {
            return Err("E-posta boş olamaz.".to_string());
        }

        let mut hasher = Sha256::new();
        hasher.update(USER_DIR_DOMAIN);
        hasher.update(email.as_bytes());
        let digest = hex::encode(hasher.finalize());

        Ok(Self::in_dir(
            app_data_dir.join(VAULTS_DIR_NAME).join(&digest[..32]),
        ))
    }

    pub fn all_files(&self) -> [&PathBuf; 5] {
        [
            &self.master_key,
            &self.owner_binding,
            &self.stronghold,
            &self.owner_binding_temp,
            &self.items_cache,
        ]
    }

    pub fn has_any_file(&self) -> bool {
        self.all_files().iter().any(|path| path.exists())
    }

    pub fn is_initialized(&self) -> bool {
        self.master_key.is_file()
    }

    pub fn is_complete(&self) -> bool {
        self.master_key.is_file()
            && self.owner_binding.is_file()
            && self.stronghold.is_file()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn users_get_separate_directories() {
        let root = tempdir().unwrap();

        let a = VaultPaths::for_email(root.path(), "a@x.com").unwrap();
        let b = VaultPaths::for_email(root.path(), "b@x.com").unwrap();
        let a_again = VaultPaths::for_email(root.path(), " A@x.com ").unwrap();

        assert_ne!(a.dir, b.dir);
        assert_eq!(a.dir, a_again.dir);
        assert!(a.dir.starts_with(root.path().join(VAULTS_DIR_NAME)));
    }

    #[test]
    fn empty_email_is_rejected() {
        let root = tempdir().unwrap();
        assert!(VaultPaths::for_email(root.path(), "  ").is_err());
    }
}
