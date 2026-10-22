use std::{
    path::Path,
    sync::{Mutex, MutexGuard},
};

#[cfg(test)]
use std::collections::HashMap;

use hkdf::Hkdf;
use sha2::Sha256;
use tauri_plugin_stronghold::stronghold::Stronghold;
use zeroize::{Zeroize, Zeroizing};

use super::KeyStore;

const SNAPSHOT_SALT: &[u8] = b"com.company.passwordmanager.stronghold.v1";
const SNAPSHOT_INFO: &[u8] = b"stronghold-snapshot-encryption-key";
const STRONGHOLD_CLIENT_ID: &[u8] = b"password-manager-secret-store-v1";

#[cfg(test)]
fn log_elapsed(stage: &str, started: std::time::Instant) {
    eprintln!(
        "[stronghold-perf] {stage}: {:.3}s",
        started.elapsed().as_secs_f64()
    );
}

pub struct PlatformKeyStore {
    stronghold: Option<Mutex<Stronghold>>,
    #[cfg(test)]
    memory: Option<Mutex<HashMap<String, Vec<u8>>>>,
}

impl PlatformKeyStore {
    pub fn open(path: &Path, master_key: &[u8; 32]) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        }

        let snapshot_exists = path.exists();
        let snapshot_key = Self::derive_snapshot_key(master_key)?;

        #[cfg(test)]
        let started = std::time::Instant::now();

        let stronghold = Stronghold::new(path, snapshot_key.to_vec())
            .map_err(|error| format!("Stronghold snapshot açılamadı: {error}"))?;

        #[cfg(test)]
        log_elapsed(
            if snapshot_exists {
                "Stronghold::new (existing snapshot)"
            } else {
                "Stronghold::new (new snapshot)"
            },
            started,
        );

        #[cfg(test)]
        let started = std::time::Instant::now();

        if snapshot_exists {
            stronghold
                .load_client(STRONGHOLD_CLIENT_ID)
                .map_err(|error| format!("Stronghold istemcisi yüklenemedi: {error}"))?;
        } else {
            stronghold
                .create_client(STRONGHOLD_CLIENT_ID)
                .map_err(|error| format!("Stronghold istemcisi oluşturulamadı: {error}"))?;
        }

        #[cfg(test)]
        log_elapsed(
            if snapshot_exists {
                "load_client"
            } else {
                "create_client"
            },
            started,
        );

        Ok(Self {
            stronghold: Some(Mutex::new(stronghold)),
            #[cfg(test)]
            memory: None,
        })
    }

    fn derive_snapshot_key(master_key: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, String> {
        let hkdf = Hkdf::<Sha256>::new(Some(SNAPSHOT_SALT), master_key);

        let mut output = Zeroizing::new([0u8; 32]);

        hkdf.expand(SNAPSHOT_INFO, &mut *output)
            .map_err(|_| "Stronghold anahtarı türetilemedi.".to_string())?;

        Ok(output)
    }

    fn lock_stronghold(&self) -> Result<MutexGuard<'_, Stronghold>, String> {
        let stronghold = self
            .stronghold
            .as_ref()
            .ok_or_else(|| "Stronghold bu test store'unda kullanılmıyor.".to_string())?;

        stronghold
            .lock()
            .map_err(|_| "Stronghold kilidi kullanılamıyor.".to_string())
    }

    /// Clears decrypted Stronghold runtime state without deleting
    /// the encrypted snapshot persisted on disk.
    pub fn clear_runtime_state(&self) -> Result<(), String> {
        #[cfg(test)]
        if let Some(memory) = &self.memory {
            let mut memory = memory
                .lock()
                .map_err(|_| "Test store kilidi kullanılamıyor.".to_string())?;

            for value in memory.values_mut() {
                value.zeroize();
            }

            memory.clear();
            return Ok(());
        }

        let stronghold = self.lock_stronghold()?;

        stronghold
            .clear()
            .map_err(|error| format!("Stronghold bellek durumu temizlenemedi: {error}"))
    }

    #[cfg(test)]
    pub fn new() -> Self {
        Self::default()
    }
}

#[cfg(test)]
impl Default for PlatformKeyStore {
    fn default() -> Self {
        Self {
            stronghold: None,
            memory: Some(Mutex::new(HashMap::new())),
        }
    }
}

impl KeyStore for PlatformKeyStore {
    fn save(&self, key: &str, value: &[u8]) -> Result<(), String> {
        if key.is_empty() {
            return Err("Secret anahtarı boş olamaz.".to_string());
        }

        #[cfg(test)]
        if let Some(memory) = &self.memory {
            let mut memory = memory
                .lock()
                .map_err(|_| "Test store kilidi kullanılamıyor.".to_string())?;

            let mut previous = memory.insert(key.to_string(), value.to_vec());

            if let Some(previous_value) = previous.as_mut() {
                previous_value.zeroize();
            }

            return Ok(());
        }

        let stronghold = self.lock_stronghold()?;

        let client = stronghold
            .get_client(STRONGHOLD_CLIENT_ID)
            .map_err(|error| error.to_string())?;

        #[cfg(test)]
        let started = std::time::Instant::now();

        client
            .store()
            .insert(key.as_bytes().to_vec(), value.to_vec(), None)
            .map_err(|error| error.to_string())?;

        #[cfg(test)]
        log_elapsed("store.insert", started);

        #[cfg(test)]
        let started = std::time::Instant::now();

        stronghold.save().map_err(|error| error.to_string())?;

        #[cfg(test)]
        log_elapsed("Stronghold::save", started);

        Ok(())
    }

    fn load(&self, key: &str) -> Result<Option<Vec<u8>>, String> {
        if key.is_empty() {
            return Err("Secret anahtarı boş olamaz.".to_string());
        }

        #[cfg(test)]
        if let Some(memory) = &self.memory {
            let memory = memory
                .lock()
                .map_err(|_| "Test store kilidi kullanılamıyor.".to_string())?;

            return Ok(memory.get(key).cloned());
        }

        let stronghold = self.lock_stronghold()?;

        let client = stronghold
            .get_client(STRONGHOLD_CLIENT_ID)
            .map_err(|error| error.to_string())?;

        #[cfg(test)]
        let started = std::time::Instant::now();

        let result = client
            .store()
            .get(key.as_bytes())
            .map_err(|error| error.to_string())?;

        #[cfg(test)]
        log_elapsed("store.get", started);

        Ok(result)
    }

    fn delete(&self, key: &str) -> Result<(), String> {
        if key.is_empty() {
            return Err("Secret anahtarı boş olamaz.".to_string());
        }

        #[cfg(test)]
        if let Some(memory) = &self.memory {
            let mut memory = memory
                .lock()
                .map_err(|_| "Test store kilidi kullanılamıyor.".to_string())?;

            if let Some(mut removed) = memory.remove(key) {
                removed.zeroize();
            }

            return Ok(());
        }

        let stronghold = self.lock_stronghold()?;

        let client = stronghold
            .get_client(STRONGHOLD_CLIENT_ID)
            .map_err(|error| error.to_string())?;

        #[cfg(test)]
        let started = std::time::Instant::now();

        let mut removed = client
            .store()
            .delete(key.as_bytes())
            .map_err(|error| error.to_string())?;

        if let Some(value) = removed.as_mut() {
            value.zeroize();
        }

        #[cfg(test)]
        log_elapsed("store.delete", started);

        #[cfg(test)]
        let started = std::time::Instant::now();

        stronghold.save().map_err(|error| error.to_string())?;

        #[cfg(test)]
        log_elapsed("Stronghold::save (delete)", started);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn unique_path() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "password-manager-stronghold-test-{}-{}.hold",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed),
        ))
    }

    #[test]
    fn test_store_can_save_load_and_delete() {
        let store = PlatformKeyStore::new();

        store.save("test-secret", b"test-value").unwrap();

        assert_eq!(
            store.load("test-secret").unwrap(),
            Some(b"test-value".to_vec()),
        );

        store.delete("test-secret").unwrap();
        assert_eq!(store.load("test-secret").unwrap(), None);
    }

    #[test]
    fn test_store_returns_none_for_missing_secret() {
        let store = PlatformKeyStore::new();
        assert_eq!(store.load("missing-secret").unwrap(), None);
    }

    #[test]
    fn test_store_clear_zeroizes_and_removes_memory_entries() {
        let store = PlatformKeyStore::new();

        store.save("secret", b"value").unwrap();
        store.clear_runtime_state().unwrap();

        assert_eq!(store.load("secret").unwrap(), None);
    }

    #[test]
    fn stronghold_snapshot_round_trip_and_wrong_key_rejection() {
        let path = unique_path();
        let master_key = [17u8; 32];

        {
            let store = PlatformKeyStore::open(&path, &master_key).unwrap();

            store.save("persisted-secret", b"persisted-value").unwrap();

            store.clear_runtime_state().unwrap();
        }

        {
            let store = PlatformKeyStore::open(&path, &master_key).unwrap();

            assert_eq!(
                store.load("persisted-secret").unwrap(),
                Some(b"persisted-value".to_vec()),
            );
        }

        assert!(PlatformKeyStore::open(&path, &[12u8; 32]).is_err());

        let _ = std::fs::remove_file(path);
    }
}
