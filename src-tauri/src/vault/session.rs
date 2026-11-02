use std::{
    sync::Mutex,
    time::{Duration, Instant},
};

use crate::{
    crypto::{identity::IdentityKeyPair, key_encryption::ProtectedMasterKey},
    storage::key_store::PlatformKeyStore,
    vault::owner_binding::VaultOwner,
};

pub const AUTO_LOCK_TIMEOUT: Duration = Duration::from_secs(5 * 60);

struct UnlockedVault {
    identity: IdentityKeyPair,
    key_store: PlatformKeyStore,
    owner: VaultOwner,
    last_activity: Instant,
    /// Sunucu parolayı onaylayana kadar diske yazılmayan yeni ana anahtar
    /// koruması (parola değişikliği).
    pending_master_key: Option<ProtectedMasterKey>,
}

pub struct VaultSession {
    vault: Mutex<Option<UnlockedVault>>,
    idle_timeout: Duration,
}

impl Default for VaultSession {
    fn default() -> Self {
        Self {
            vault: Mutex::new(None),
            idle_timeout: AUTO_LOCK_TIMEOUT,
        }
    }
}

impl VaultSession {
    pub fn new() -> Self {
        Self::default()
    }

    #[cfg(test)]
    fn with_idle_timeout(idle_timeout: Duration) -> Self {
        Self {
            vault: Mutex::new(None),
            idle_timeout,
        }
    }

    /// Kasayı oturumdan çıkarır ve Stronghold'un çözülmüş bellek durumunu
    /// temizler. Kimlik anahtarı `Zeroizing` içinde tutulduğu için drop
    /// sırasında silinir.
    fn release(vault: &mut Option<UnlockedVault>) -> Result<(), String> {
        let Some(unlocked) = vault.take() else {
            return Ok(());
        };

        let clear_result = unlocked.key_store.clear_runtime_state();
        drop(unlocked);

        clear_result
    }

    fn expire_if_needed(
        vault: &mut Option<UnlockedVault>,
        idle_timeout: Duration,
    ) -> Result<bool, String> {
        let expired = vault
            .as_ref()
            .is_some_and(|unlocked| unlocked.last_activity.elapsed() >= idle_timeout);

        if !expired {
            return Ok(false);
        }

        Self::release(vault)?;
        Ok(true)
    }

    fn guard(&self) -> Result<std::sync::MutexGuard<'_, Option<UnlockedVault>>, String> {
        self.vault
            .lock()
            .map_err(|_| "Vault session lock poisoned".to_string())
    }

    pub fn is_unlocked(&self) -> Result<bool, String> {
        Ok(self.current_owner()?.is_some())
    }

    /// Açık kasanın sahibi; kasa kilitliyse `None`.
    pub fn current_owner(&self) -> Result<Option<VaultOwner>, String> {
        let mut guard = self.guard()?;

        Self::expire_if_needed(&mut guard, self.idle_timeout)?;

        Ok(guard.as_ref().map(|unlocked| unlocked.owner.clone()))
    }

    pub fn unlock(
        &self,
        identity: IdentityKeyPair,
        key_store: PlatformKeyStore,
        owner: VaultOwner,
    ) -> Result<(), String> {
        let mut guard = self.guard()?;

        // Başka bir hesabın kasası açık kalmışsa önce kapatılır.
        Self::release(&mut guard)?;

        *guard = Some(UnlockedVault {
            identity,
            key_store,
            owner,
            last_activity: Instant::now(),
            pending_master_key: None,
        });

        Ok(())
    }

    pub fn lock(&self) -> Result<(), String> {
        let mut guard = self.guard()?;

        Self::release(&mut guard)
    }

    pub fn lock_if_idle(&self) -> Result<bool, String> {
        let mut guard = self.guard()?;

        Self::expire_if_needed(&mut guard, self.idle_timeout)
    }

    pub fn record_activity(&self) -> Result<(), String> {
        self.with_identity(|_, _| Ok(()))
    }

    /// Kasa açıksa kimlik anahtarıyla işlem yapar ve etkinlik zamanını
    /// günceller.
    pub fn with_identity<T>(
        &self,
        operation: impl FnOnce(&IdentityKeyPair, &VaultOwner) -> Result<T, String>,
    ) -> Result<T, String> {
        self.with_vault(|identity, owner, _| operation(identity, owner))
    }

    /// `with_identity` gibi; ayrıca kasadaki gizli anahtar deposuna erişir.
    pub fn with_vault<T>(
        &self,
        operation: impl FnOnce(&IdentityKeyPair, &VaultOwner, &PlatformKeyStore) -> Result<T, String>,
    ) -> Result<T, String> {
        let mut guard = self.guard()?;

        if Self::expire_if_needed(&mut guard, self.idle_timeout)? {
            return Err("Kasa hareketsizlik nedeniyle kilitlendi.".to_string());
        }

        let unlocked = guard.as_mut().ok_or_else(|| "Kasa kilitli.".to_string())?;

        unlocked.last_activity = Instant::now();

        operation(&unlocked.identity, &unlocked.owner, &unlocked.key_store)
    }

    pub fn set_pending_master_key(&self, protected: ProtectedMasterKey) -> Result<(), String> {
        let mut guard = self.guard()?;
        let unlocked = guard.as_mut().ok_or_else(|| "Kasa kilitli.".to_string())?;

        unlocked.pending_master_key = Some(protected);
        Ok(())
    }

    pub fn take_pending_master_key(&self) -> Result<(VaultOwner, ProtectedMasterKey), String> {
        let mut guard = self.guard()?;
        let unlocked = guard.as_mut().ok_or_else(|| "Kasa kilitli.".to_string())?;

        let protected = unlocked
            .pending_master_key
            .take()
            .ok_or_else(|| "Bekleyen parola değişikliği yok.".to_string())?;

        Ok((unlocked.owner.clone(), protected))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    fn owner(email: &str) -> VaultOwner {
        VaultOwner {
            email: email.to_string(),
            user_id: format!("id-{email}"),
        }
    }

    fn create_unlocked_session(idle_timeout: Duration, email: &str) -> VaultSession {
        let session = VaultSession::with_idle_timeout(idle_timeout);

        session
            .unlock(IdentityKeyPair::generate(), PlatformKeyStore::new(), owner(email))
            .expect("session should unlock");

        session
    }

    #[test]
    fn idle_session_is_locked() {
        let session = create_unlocked_session(Duration::from_millis(50), "a@x.com");

        assert!(session.is_unlocked().unwrap());

        thread::sleep(Duration::from_millis(100));

        assert!(session.lock_if_idle().unwrap());
        assert!(!session.is_unlocked().unwrap());
    }

    #[test]
    fn recent_activity_resets_idle_timeout() {
        let session = create_unlocked_session(Duration::from_millis(300), "a@x.com");

        thread::sleep(Duration::from_millis(180));

        session
            .record_activity()
            .expect("activity should extend the timeout");

        thread::sleep(Duration::from_millis(180));

        assert!(!session.lock_if_idle().unwrap());

        thread::sleep(Duration::from_millis(350));

        assert!(session.lock_if_idle().unwrap());
        assert!(!session.is_unlocked().unwrap());
    }

    #[test]
    fn unlocking_another_account_replaces_the_session() {
        let session = create_unlocked_session(Duration::from_secs(30), "a@x.com");

        session
            .unlock(IdentityKeyPair::generate(), PlatformKeyStore::new(), owner("b@x.com"))
            .unwrap();

        assert_eq!(session.current_owner().unwrap(), Some(owner("b@x.com")));
    }

    #[test]
    fn expired_session_cannot_be_revived_by_activity() {
        let session = create_unlocked_session(Duration::from_millis(50), "a@x.com");

        thread::sleep(Duration::from_millis(100));

        assert!(session.record_activity().is_err());
        assert!(!session.is_unlocked().unwrap());
    }

    #[test]
    fn manual_lock_is_idempotent() {
        let session = create_unlocked_session(Duration::from_secs(30), "a@x.com");

        session.lock().expect("manual lock should succeed");
        session
            .lock()
            .expect("locking an already locked vault should succeed");

        assert!(!session.is_unlocked().unwrap());
    }

    #[test]
    fn pending_master_key_is_cleared_on_lock() {
        let session = create_unlocked_session(Duration::from_secs(30), "a@x.com");

        session
            .set_pending_master_key(ProtectedMasterKey {
                ciphertext: vec![1],
                nonce: [0; 12],
                kdf_version: 2,
            })
            .unwrap();

        session.lock().unwrap();

        assert!(session.take_pending_master_key().is_err());
    }
}
