use argon2::{Algorithm, Argon2, Params, Version};
use rand::Rng;
use zeroize::Zeroizing;

const KEY_LENGTH: usize = 32;
const SALT_LENGTH: usize = 16;

const MEMORY_COST_KIB: u32 = 64 * 1024;
const TIME_COST: u32 = 3;
const PARALLELISM: u32 = 4;

const KDF_VERSION: u8 = 1;

const AUTH_DOMAIN: &[u8] = b"password-manager/auth/v1";
const KEK_DOMAIN: &[u8] = b"password-manager/kek/v1";

pub struct DerivedKey {
    pub key: Zeroizing<[u8; KEY_LENGTH]>,
    pub salt: [u8; SALT_LENGTH],
}

#[derive(Debug, Clone, Copy)]
pub enum KeyPurpose {
    Authentication,
    KeyEncryption,
}

impl KeyPurpose {
    fn domain(self) -> &'static [u8] {
        match self {
            Self::Authentication => AUTH_DOMAIN,
            Self::KeyEncryption => KEK_DOMAIN,
        }
    }
}

pub fn generate_salt() -> [u8; SALT_LENGTH] {
    rand::rng().random()
}

pub fn derive_key(
    password: &[u8],
    salt: [u8; SALT_LENGTH],
    purpose: KeyPurpose,
) -> Result<DerivedKey, String> {
    let params = Params::new(MEMORY_COST_KIB, TIME_COST, PARALLELISM, Some(KEY_LENGTH))
        .map_err(|error| error.to_string())?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = Zeroizing::new([0u8; KEY_LENGTH]);

    let mut password_with_domain = Vec::with_capacity(purpose.domain().len() + password.len());

    password_with_domain.extend_from_slice(purpose.domain());
    password_with_domain.extend_from_slice(password);

    argon2
        .hash_password_into(&password_with_domain, &salt, &mut *key)
        .map_err(|error| error.to_string())?;

    Ok(DerivedKey { key, salt })
}

pub fn kdf_version() -> u8 {
    KDF_VERSION
}
