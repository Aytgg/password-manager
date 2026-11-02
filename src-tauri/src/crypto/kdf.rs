//! Kullanıcının tek parolasından iki bağımsız anahtar türetilir:
//!
//! - `auth_secret`: sunucuya (Convex Auth) giriş için gönderilen değer.
//! - `kek`: yerel ana anahtarı şifreleyen anahtar. Cihazdan hiç çıkmaz.
//!
//! İkisi aynı Argon2id çıktısından HKDF ile farklı etiketlerle türetildiği
//! için sunucu `auth_secret`'ı görse bile `kek`'e ulaşamaz. Tuz e-postadan
//! türetilir; böylece yeni bir cihaz, sunucuya sormadan aynı `auth_secret`'ı
//! üretebilir.

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const KEY_LENGTH: usize = 32;
const SALT_LENGTH: usize = 16;

const MEMORY_COST_KIB: u32 = 64 * 1024;
const TIME_COST: u32 = 3;
const PARALLELISM: u32 = 4;

const KDF_VERSION: u8 = 2;

const SALT_DOMAIN: &[u8] = b"password-manager/kdf-salt/v2:";
const AUTH_INFO: &[u8] = b"password-manager/auth/v2";
const KEK_INFO: &[u8] = b"password-manager/kek/v2";

const INVITE_SALT_DOMAIN: &[u8] = b"password-manager/invite-salt/v1:";
const INVITE_IDENTITY_INFO: &[u8] = b"password-manager/invite-identity/v1";
const INVITE_VERIFIER_INFO: &[u8] = b"password-manager/invite-verifier/v1";

pub struct PasswordKeys {
    pub auth_secret: Zeroizing<[u8; KEY_LENGTH]>,
    pub kek: Zeroizing<[u8; KEY_LENGTH]>,
}

/// Sunucuyla aynı kuralla normalleştirilir (`convex/lib.ts` normalizeEmail).
pub fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}

/// Davet kodundan türetilen anahtarlar. `identity_private_key` davet edilen
/// kullanıcının kayıt olana kadarki geçici X25519 kimliğidir; `verifier`
/// kayıt sırasında sunucuya kodu bildiğini kanıtlar (sunucu yalnızca
/// özetini saklar).
pub struct InviteKeys {
    pub identity_private_key: Zeroizing<[u8; KEY_LENGTH]>,
    pub verifier: Zeroizing<[u8; KEY_LENGTH]>,
}

/// Tuz e-postadan türetilir; böylece her cihaz aynı anahtarı üretir.
fn salt_for(domain: &[u8], email: &str) -> [u8; SALT_LENGTH] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(normalize_email(email).as_bytes());

    let mut salt = [0u8; SALT_LENGTH];
    salt.copy_from_slice(&hasher.finalize()[..SALT_LENGTH]);
    salt
}

/// Argon2id ile gerer ve çıktıyı HKDF ile her etiket için ayrı anahtara açar.
fn stretch_and_expand<const N: usize>(
    secret: &[u8],
    salt: [u8; SALT_LENGTH],
    infos: [&[u8]; N],
) -> Result<[Zeroizing<[u8; KEY_LENGTH]>; N], String> {
    let params = Params::new(MEMORY_COST_KIB, TIME_COST, PARALLELISM, Some(KEY_LENGTH))
        .map_err(|error| error.to_string())?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut stretched = Zeroizing::new([0u8; KEY_LENGTH]);

    argon2
        .hash_password_into(secret, &salt, &mut *stretched)
        .map_err(|error| error.to_string())?;

    let hkdf = Hkdf::<Sha256>::from_prk(&*stretched)
        .map_err(|_| "Anahtar genişletilemedi.".to_string())?;

    let mut keys = std::array::from_fn(|_| Zeroizing::new([0u8; KEY_LENGTH]));

    for (key, info) in keys.iter_mut().zip(infos) {
        hkdf.expand(info, &mut **key)
            .map_err(|_| "Anahtar türetilemedi.".to_string())?;
    }

    Ok(keys)
}

pub fn derive_password_keys(email: &str, password: &[u8]) -> Result<PasswordKeys, String> {
    if normalize_email(email).is_empty() {
        return Err("E-posta boş olamaz.".to_string());
    }

    let [auth_secret, kek] =
        stretch_and_expand(password, salt_for(SALT_DOMAIN, email), [AUTH_INFO, KEK_INFO])?;

    Ok(PasswordKeys { auth_secret, kek })
}

/// Büyük/küçük harf, boşluk ve tireden bağımsız hale getirir.
pub fn normalize_invite_code(code: &str) -> String {
    code.chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

pub fn derive_invite_keys(email: &str, code: &str) -> Result<InviteKeys, String> {
    let code = normalize_invite_code(code);

    if normalize_email(email).is_empty() || code.is_empty() {
        return Err("E-posta ve davet kodu gerekli.".to_string());
    }

    let [identity_private_key, verifier] = stretch_and_expand(
        code.as_bytes(),
        salt_for(INVITE_SALT_DOMAIN, email),
        [INVITE_IDENTITY_INFO, INVITE_VERIFIER_INFO],
    )?;

    Ok(InviteKeys {
        identity_private_key,
        verifier,
    })
}

pub fn kdf_version() -> u8 {
    KDF_VERSION
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_inputs_give_same_keys() {
        let a = derive_password_keys("User@Example.com ", b"password").unwrap();
        let b = derive_password_keys("user@example.com", b"password").unwrap();

        assert_eq!(*a.auth_secret, *b.auth_secret);
        assert_eq!(*a.kek, *b.kek);
    }

    #[test]
    fn auth_secret_and_kek_differ() {
        let keys = derive_password_keys("user@example.com", b"password").unwrap();

        assert_ne!(*keys.auth_secret, *keys.kek);
    }

    #[test]
    fn email_and_password_both_change_the_keys() {
        let base = derive_password_keys("a@example.com", b"password").unwrap();
        let other_email = derive_password_keys("b@example.com", b"password").unwrap();
        let other_password = derive_password_keys("a@example.com", b"password2").unwrap();

        assert_ne!(*base.kek, *other_email.kek);
        assert_ne!(*base.kek, *other_password.kek);
    }

    #[test]
    fn empty_email_is_rejected() {
        assert!(derive_password_keys("  ", b"password").is_err());
    }

    #[test]
    fn invite_code_format_does_not_matter() {
        let a = derive_invite_keys("a@x.com", "abcd-efgh-jkmn").unwrap();
        let b = derive_invite_keys("A@x.com", " ABCDEFGH JKMN ").unwrap();

        assert_eq!(*a.identity_private_key, *b.identity_private_key);
        assert_eq!(*a.verifier, *b.verifier);
        assert_ne!(*a.identity_private_key, *a.verifier);
    }

    #[test]
    fn invite_keys_differ_from_password_keys() {
        let invite = derive_invite_keys("a@x.com", "ABCD").unwrap();
        let password = derive_password_keys("a@x.com", b"ABCD").unwrap();

        assert_ne!(*invite.verifier, *password.auth_secret);
        assert_ne!(*invite.identity_private_key, *password.kek);
    }
}
