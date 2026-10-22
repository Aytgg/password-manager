use crate::crypto::identity::IdentityKeyPair;

use super::KeyStore;

pub(super) const IDENTITY_PRIVATE_KEY_PREFIX: &str = "identity-private-key";

pub struct LoadedIdentity {
    pub identity: IdentityKeyPair,
    pub created: bool,
}

/// Var olan kimlik anahtarını yükler. Anahtar yoksa yenisini üretmez;
/// sessizce yeni anahtar üretmek, bu hesaba paylaşılmış tüm kayıtları
/// okunamaz hale getirirdi.
pub fn load_identity<K: KeyStore>(store: &K, user_id: &str) -> Result<IdentityKeyPair, String> {
    if user_id.trim().is_empty() {
        return Err("User ID cannot be empty".to_string());
    }

    let key_name = format!("{IDENTITY_PRIVATE_KEY_PREFIX}:{user_id}");

    let bytes = store
        .load(&key_name)?
        .ok_or_else(|| "Kasada bu hesaba ait kimlik anahtarı bulunamadı.".to_string())?;

    let private_bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "Invalid identity private key length".to_string())?;

    Ok(IdentityKeyPair::from_private_key(private_bytes))
}

pub fn load_or_create_identity<K: KeyStore>(
    store: &K,
    user_id: &str,
) -> Result<LoadedIdentity, String> {
    if user_id.trim().is_empty() {
        return Err("User ID cannot be empty".to_string());
    }

    let key_name = format!("{IDENTITY_PRIVATE_KEY_PREFIX}:{user_id}");

    match store.load(&key_name)? {
        Some(bytes) => {
            let private_bytes: [u8; 32] = bytes
                .try_into()
                .map_err(|_| "Invalid identity private key length".to_string())?;

            Ok(LoadedIdentity {
                identity: IdentityKeyPair::from_private_key(private_bytes),
                created: false,
            })
        }
        None => {
            let identity = IdentityKeyPair::generate();

            store.save(&key_name, identity.private_key())?;

            Ok(LoadedIdentity {
                identity,
                created: true,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::key_store::PlatformKeyStore;

    #[test]
    fn identity_is_restored_from_keychain() {
        let store = PlatformKeyStore::new();
        let user_id = format!("test-user-{}", std::process::id());

        let identity =
            load_or_create_identity(&store, &user_id).expect("identity should be created");

        let original_public_key = identity.identity.public_key();

        let restored =
            load_or_create_identity(&store, &user_id).expect("identity should be restored");

        assert_eq!(original_public_key, restored.identity.public_key());

        store
            .delete(&format!("{IDENTITY_PRIVATE_KEY_PREFIX}:{user_id}"))
            .expect("test key should be deleted");
    }

    #[test]
    fn different_users_have_different_identities() {
        let store = PlatformKeyStore::new();
        let suffix = std::process::id();

        let user_a = format!("test-user-a-{suffix}");
        let user_b = format!("test-user-b-{suffix}");

        let identity_a =
            load_or_create_identity(&store, &user_a).expect("first identity should be created");

        let identity_b =
            load_or_create_identity(&store, &user_b).expect("second identity should be created");

        assert_ne!(
            identity_a.identity.public_key(),
            identity_b.identity.public_key()
        );

        store
            .delete(&format!("{IDENTITY_PRIVATE_KEY_PREFIX}:{user_a}"))
            .expect("first test key should be deleted");

        store
            .delete(&format!("{IDENTITY_PRIVATE_KEY_PREFIX}:{user_b}"))
            .expect("second test key should be deleted");
    }

    #[test]
    fn empty_user_id_is_rejected() {
        let store = PlatformKeyStore::new();

        assert!(load_or_create_identity(&store, "").is_err());
        assert!(load_or_create_identity(&store, "   ").is_err());
    }
}
