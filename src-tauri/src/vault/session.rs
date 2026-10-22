use std::{
    sync::Mutex,
    time::{Duration, Instant},
};

use crate::{crypto::identity::IdentityKeyPair, storage::key_store::PlatformKeyStore};

pub const AUTO_LOCK_TIMEOUT: Duration = Duration::from_secs(5 * 60);

struct UnlockedVault {
    identity: IdentityKeyPair,
    key_store: PlatformKeyStore,
    clerk_user_id: String,
    last_activity: Instant,
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

    fn remove_if_wrong_user(
        vault: &mut Option<UnlockedVault>,
        requested_user_id: &str,
    ) -> Result<bool, String> {
        let wrong_user = vault
            .as_ref()
            .is_some_and(|unlocked| unlocked.clerk_user_id != requested_user_id);

        if !wrong_user {
            return Ok(false);
        }

        Self::release(vault)?;
        Ok(true)
    }

    pub fn is_unlocked(&self) -> Result<bool, String> {
        self.lock_if_idle()?;

        let guard = self
            .vault
            .lock()
            .map_err(|_| "Vault session lock poisoned".to_string())?;

        Ok(guard.is_some())
    }

    pub fn is_unlocked_for_user(&self, user_id: &str) -> Result<bool, String> {
        let user_id = user_id.trim();

        if user_id.is_empty() {
            return Err("Clerk kullanıcı kimliği boş olamaz.".to_string());
        }

        self.lock_if_idle()?;

        let mut guard = self
            .vault
            .lock()
            .map_err(|_| "Vault session lock poisoned".to_string())?;

        if Self::remove_if_wrong_user(&mut guard, user_id)? {
            return Ok(false);
        }

        Ok(guard.is_some())
    }

    pub fn unlock(
        &self,
        identity: IdentityKeyPair,
        key_store: PlatformKeyStore,
        clerk_user_id: String,
    ) -> Result<(), String> {
        let clerk_user_id = clerk_user_id.trim().to_string();

        if clerk_user_id.is_empty() {
            return Err("Clerk kullanıcı kimliği boş olamaz.".to_string());
        }

        let mut guard = self
            .vault
            .lock()
            .map_err(|_| "Vault session lock poisoned".to_string())?;

        if guard.is_some() {
            return Err("Vault is already unlocked".to_string());
        }

        *guard = Some(UnlockedVault {
            identity,
            key_store,
            clerk_user_id,
            last_activity: Instant::now(),
        });

        Ok(())
    }

    pub fn lock(&self) -> Result<(), String> {
        let mut guard = self
            .vault
            .lock()
            .map_err(|_| "Vault session lock poisoned".to_string())?;

        Self::release(&mut guard)
    }

    pub fn lock_if_idle(&self) -> Result<bool, String> {
        let mut guard = self
            .vault
            .lock()
            .map_err(|_| "Vault session lock poisoned".to_string())?;

        Self::expire_if_needed(&mut guard, self.idle_timeout)
    }

    pub fn record_activity_for_user(&self, user_id: &str) -> Result<(), String> {
        self.with_identity_for_user(user_id, |_| Ok(()))
    }

    /// Kasa bu kullanıcı için açıksa kimlik anahtarıyla işlem yapar ve
    /// etkinlik zamanını günceller.
    pub fn with_identity_for_user<T>(
        &self,
        user_id: &str,
        operation: impl FnOnce(&IdentityKeyPair) -> Result<T, String>,
    ) -> Result<T, String> {
        let user_id = user_id.trim();

        if user_id.is_empty() {
            return Err("Clerk kullanıcı kimliği boş olamaz.".to_string());
        }

        let mut guard = self
            .vault
            .lock()
            .map_err(|_| "Vault session lock poisoned".to_string())?;

        if Self::expire_if_needed(&mut guard, self.idle_timeout)? {
            return Err("Kasa hareketsizlik nedeniyle kilitlendi.".to_string());
        }

        if Self::remove_if_wrong_user(&mut guard, user_id)? {
            return Err(
                "Kasa başka bir Clerk hesabına bağlıydı ve güvenlik için kilitlendi."
                    .to_string(),
            );
        }

        let unlocked = guard.as_mut().ok_or_else(|| "Vault is locked".to_string())?;

        unlocked.last_activity = Instant::now();

        operation(&unlocked.identity)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    fn create_unlocked_session(idle_timeout: Duration, user_id: &str) -> VaultSession {
        let session = VaultSession::with_idle_timeout(idle_timeout);

        session
            .unlock(
                IdentityKeyPair::generate(),
                PlatformKeyStore::new(),
                user_id.to_string(),
            )
            .expect("session should unlock");

        session
    }

    #[test]
    fn idle_session_is_locked() {
        let session = create_unlocked_session(Duration::from_millis(50), "test-user");

        assert!(session.is_unlocked_for_user("test-user").unwrap());

        thread::sleep(Duration::from_millis(100));

        assert!(session.lock_if_idle().unwrap());
        assert!(!session.is_unlocked().unwrap());
    }

    #[test]
    fn recent_activity_resets_idle_timeout() {
        let session = create_unlocked_session(Duration::from_millis(300), "test-user");

        thread::sleep(Duration::from_millis(180));

        session
            .record_activity_for_user("test-user")
            .expect("activity should extend the timeout");

        thread::sleep(Duration::from_millis(180));

        assert!(!session.lock_if_idle().unwrap());

        thread::sleep(Duration::from_millis(350));

        assert!(session.lock_if_idle().unwrap());
        assert!(!session.is_unlocked().unwrap());
    }

    #[test]
    fn wrong_user_locks_the_current_session() {
        let session = create_unlocked_session(Duration::from_secs(30), "user-a");

        assert!(!session.is_unlocked_for_user("user-b").unwrap());
        assert!(!session.is_unlocked().unwrap());
    }

    #[test]
    fn wrong_user_cannot_use_the_identity() {
        let session = create_unlocked_session(Duration::from_secs(30), "user-a");

        let result = session.with_identity_for_user("user-b", |_| Ok(()));

        assert!(result.is_err());
        assert!(!session.is_unlocked().unwrap());
    }

    #[test]
    fn expired_session_cannot_be_revived_by_activity() {
        let session = create_unlocked_session(Duration::from_millis(50), "test-user");

        thread::sleep(Duration::from_millis(100));

        assert!(session.record_activity_for_user("test-user").is_err());
        assert!(!session.is_unlocked().unwrap());
    }

    #[test]
    fn manual_lock_is_idempotent() {
        let session = create_unlocked_session(Duration::from_secs(30), "test-user");

        session.lock().expect("manual lock should succeed");
        session
            .lock()
            .expect("locking an already locked vault should succeed");

        assert!(!session.is_unlocked().unwrap());
    }
}
