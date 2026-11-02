//! Davet kodları ve davet edilen kullanıcının geçici kimliği.
//!
//! Davet kodu yöneticinin cihazında üretilir; sunucu kodu hiç görmez. Koddan
//! (e-posta tuzuyla, Argon2id) bir geçici X25519 kimliği ve bir doğrulayıcı
//! türetilir. Sunucuya yalnızca açık anahtar ve doğrulayıcı gider. Böylece
//! kullanıcı kaydolmadan önce de ona şifre ve departman anahtarı
//! paketlenebilir. Kullanıcı kaydolunca bunları kendi kalıcı kimliğine
//! yeniden paketler ve geçici kimlik kullanılmaz hale gelir.

use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::crypto::{identity::IdentityKeyPair, kdf};
use crate::vault::items::{encode_public_key, unwrap_key, wrap_for, WrappedKeyDto};

// Karışması kolay karakterler (0/O, 1/I/L) bilinçli olarak yok.
const ALPHABET: &[u8] = b"23456789ABCDEFGHJKMNPQRSTUVWXYZ";
const CODE_LENGTH: usize = 12;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreparedInvite {
    /// Kullanıcıya iletilecek kod; yalnızca bir kez gösterilir.
    pub code: String,
    pub public_key: String,
    pub verifier: String,
}

fn generate_code() -> String {
    let mut rng = rand::rng();
    // Eşit dağılım için alfabe boyunun katı olmayan baytlar atlanır.
    let limit = (256 / ALPHABET.len() * ALPHABET.len()) as u8;

    let raw: Vec<u8> = std::iter::repeat_with(|| rng.random::<u8>())
        .filter(|byte| *byte < limit)
        .take(CODE_LENGTH)
        .map(|byte| ALPHABET[byte as usize % ALPHABET.len()])
        .collect();

    raw.chunks(4)
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect::<Vec<_>>()
        .join("-")
}

pub fn invite_identity(email: &str, code: &str) -> Result<IdentityKeyPair, String> {
    let keys = kdf::derive_invite_keys(email, code)?;
    Ok(IdentityKeyPair::from_private_key(*keys.identity_private_key))
}

pub fn invite_verifier(email: &str, code: &str) -> Result<String, String> {
    let keys = kdf::derive_invite_keys(email, code)?;
    Ok(hex::encode(*keys.verifier))
}

pub fn prepare_invite(email: &str) -> Result<PreparedInvite, String> {
    let code = generate_code();
    let keys = kdf::derive_invite_keys(email, &code)?;
    let identity = IdentityKeyPair::from_private_key(*keys.identity_private_key);

    Ok(PreparedInvite {
        public_key: encode_public_key(&identity.public_key()),
        verifier: hex::encode(*keys.verifier),
        code,
    })
}

/// Sunucudaki bir anahtar paketi; `id` çağıran için opaktır (kayıt erişimi
/// ya da departman anahtarı satırı).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyedAccess {
    pub id: String,
    pub access: WrappedKeyDto,
}

/// Geçici kimliğe paketlenmiş anahtarları kalıcı kimliğe yeniden paketler.
pub fn rewrap(
    from: &IdentityKeyPair,
    to: &IdentityKeyPair,
    keys: &[KeyedAccess],
) -> Result<Vec<KeyedAccess>, String> {
    keys.iter()
        .map(|key| {
            let plaintext = unwrap_key(&from.private_secret(), &key.access)
                .map_err(|_| "Davet anahtarına paketlenmiş bir anahtar açılamadı.".to_string())?;

            Ok(KeyedAccess {
                id: key.id.clone(),
                access: wrap_for(&plaintext, &to.public_key())?,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_has_expected_format() {
        let code = generate_code();

        assert_eq!(code.len(), 14);
        assert!(code.split('-').all(|part| part.len() == 4
            && part.bytes().all(|byte| ALPHABET.contains(&byte))));
        assert_ne!(code, generate_code());
    }

    #[test]
    fn prepared_invite_matches_what_the_invitee_derives() {
        let invite = prepare_invite("new@x.com").unwrap();
        let identity = invite_identity("NEW@x.com", &invite.code.to_lowercase()).unwrap();

        assert_eq!(encode_public_key(&identity.public_key()), invite.public_key);
        assert_eq!(invite_verifier("new@x.com", &invite.code).unwrap(), invite.verifier);
    }

    #[test]
    fn keys_wrapped_to_the_invite_move_to_the_permanent_identity() {
        let invite = prepare_invite("new@x.com").unwrap();
        let provisional = invite_identity("new@x.com", &invite.code).unwrap();
        let permanent = IdentityKeyPair::generate();

        let secret = [5u8; 32];
        let keys = [KeyedAccess {
            id: "a1".to_string(),
            access: wrap_for(&secret, &provisional.public_key()).unwrap(),
        }];

        let moved = rewrap(&provisional, &permanent, &keys).unwrap();

        assert_eq!(moved[0].id, "a1");
        assert_eq!(*unwrap_key(&permanent.private_secret(), &moved[0].access).unwrap(), secret);
        assert!(rewrap(&IdentityKeyPair::generate(), &permanent, &keys).is_err());
    }

    #[test]
    fn invite_is_bound_to_the_email() {
        let invite = prepare_invite("new@x.com").unwrap();
        let identity = invite_identity("other@x.com", &invite.code).unwrap();

        assert_ne!(encode_public_key(&identity.public_key()), invite.public_key);
    }
}
