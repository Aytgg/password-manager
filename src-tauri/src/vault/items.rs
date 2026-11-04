//! Convex'te saklanan parola kayıtlarının istemci tarafı şifrelemesi.
//!
//! Her kayıt rastgele bir DEK ile şifrelenir. Kayıt iki ayrı şifreli alan
//! taşır: meta veri (başlık, kullanıcı adı) ve gizli değer (parola). Böylece
//! liste görüntülenirken parolanın kendisi çözülmez. DEK, doğrudan erişimi
//! olan her kullanıcının ve paylaşıldığı her departmanın X25519 açık
//! anahtarına ayrı ayrı paketlenir. Sunucu yalnızca şifreli veriyi ve
//! paketlenmiş anahtarları görür.
//!
//! Kayıt her değiştiğinde (başlık, kullanıcı adı ya da parola) önceki hali
//! aynı DEK ile şifrelenmiş ayrı bir geçmiş kaydı olarak saklanır. Böylece
//! kaydı açabilen herkes geçmişini de açabilir; her rekey'de bütün geçmiş
//! kayıtları da yeni DEK'e taşınır.

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::crypto::{
    identity::IdentityKeyPair,
    key_wrap::{self, WrappedKey},
    password_encryption,
};

const MAX_TITLE_CHARS: usize = 200;
const MAX_USERNAME_CHARS: usize = 320;
const MAX_SECRET_BYTES: usize = 4096;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SealedField {
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WrappedKeyDto {
    pub ephemeral_public_key: String,
    pub nonce: String,
    pub ciphertext: String,
}

/// Çağıranın kaydın DEK'ine ulaşma yolu.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum ItemAccess {
    /// DEK doğrudan çağıranın açık anahtarına paketli.
    #[serde(rename_all = "camelCase")]
    Direct { access: WrappedKeyDto },
    /// DEK departmanın açık anahtarına, departmanın özel anahtarı da
    /// çağıranın açık anahtarına paketli.
    #[serde(rename_all = "camelCase")]
    Department {
        department_key: WrappedKeyDto,
        item_key: WrappedKeyDto,
    },
}

/// Convex'ten gelen bir kayıt ve çağıranın ona erişim yolu.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedItem {
    pub item_id: String,
    pub owner_id: String,
    pub metadata: SealedField,
    pub secret: SealedField,
    pub access: ItemAccess,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NewItem {
    pub item_id: String,
    pub metadata: SealedField,
    pub secret: SealedField,
    pub owner_access: WrappedKeyDto,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Recipient {
    pub user_id: String,
    pub public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecipientAccess {
    pub user_id: String,
    pub access: WrappedKeyDto,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DepartmentRecipient {
    pub department_id: String,
    pub key_version: u32,
    pub public_key: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DepartmentAccess {
    pub department_id: String,
    pub key_version: u32,
    pub access: WrappedKeyDto,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RekeyedItem {
    pub metadata: SealedField,
    pub secret: SealedField,
    /// Bütün geçmiş kayıtları yeni DEK ile; mevcutlar kimlikleriyle, bu
    /// düzenlemeyle eklenen (varsa) kimliksiz.
    pub history: Vec<HistoryRecord>,
    pub accesses: Vec<RecipientAccess>,
    pub department_accesses: Vec<DepartmentAccess>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ItemMetadata {
    pub title: String,
    pub username: Option<String>,
}

fn new_item_id() -> String {
    let mut bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    format!("item-{}", hex::encode(bytes))
}

// Şifreli alanlar sahibine ve kayıt kimliğine bağlanır; sunucu bir kaydın
// şifreli verisini başka bir kayda taşırsa çözme başarısız olur.
fn metadata_aad(owner_id: &str, item_id: &str) -> Vec<u8> {
    format!("password-manager/item/v1/metadata:{owner_id}:{item_id}").into_bytes()
}

fn secret_aad(owner_id: &str, item_id: &str) -> Vec<u8> {
    format!("password-manager/item/v1/secret:{owner_id}:{item_id}").into_bytes()
}

fn history_aad(owner_id: &str, item_id: &str) -> Vec<u8> {
    format!("password-manager/item/v1/history:{owner_id}:{item_id}").into_bytes()
}

/// Sunucudaki bir geçmiş kaydı: kaydın önceki hali, DEK ile şifreli.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryRecord {
    /// Sunucudaki kimlik; yeni eklenen kayıtta yok.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub entry: SealedField,
}

/// Kaydın bir önceki hali. Parola base64 olarak tutulur.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
struct HistoryEntry {
    title: String,
    username: Option<String>,
    password: String,
    replaced_at: u64,
}

/// Arayüze dönen geçmiş satırı; parolanın kendisini içermez.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HistoryInfo {
    pub id: String,
    /// Bu halin yerini yenisine bıraktığı an (Unix ms).
    pub replaced_at: u64,
    pub title: String,
    pub username: Option<String>,
    /// Bir sonraki halde değişenler.
    pub title_changed: bool,
    pub username_changed: bool,
    pub password_changed: bool,
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn open_history_entry(
    record: &HistoryRecord,
    dek: &[u8; 32],
    aad: &[u8],
) -> Result<HistoryEntry, String> {
    let plaintext = open(&record.entry, dek, aad)
        .map_err(|_| "Parola geçmişi çözülemedi.".to_string())?;

    serde_json::from_slice(&plaintext).map_err(|_| "Parola geçmişi okunamadı.".to_string())
}

fn decode_fixed<const N: usize>(value: &str, field: &str) -> Result<[u8; N], String> {
    BASE64
        .decode(value)
        .map_err(|_| format!("{field} base64 olarak çözülemedi."))?
        .try_into()
        .map_err(|_| format!("{field} uzunluğu geçersiz."))
}

fn decode_vec(value: &str, field: &str) -> Result<Vec<u8>, String> {
    BASE64
        .decode(value)
        .map_err(|_| format!("{field} base64 olarak çözülemedi."))
}

pub fn encode_public_key(public_key: &PublicKey) -> String {
    BASE64.encode(public_key.as_bytes())
}

pub(crate) fn decode_public_key(value: &str) -> Result<PublicKey, String> {
    Ok(PublicKey::from(decode_fixed::<32>(value, "Açık anahtar")?))
}

fn seal(plaintext: &[u8], dek: &[u8; 32], aad: &[u8]) -> Result<SealedField, String> {
    let (ciphertext, nonce) = password_encryption::encrypt_password(plaintext, dek, aad)?;

    Ok(SealedField {
        nonce: BASE64.encode(nonce),
        ciphertext: BASE64.encode(ciphertext),
    })
}

fn open(field: &SealedField, dek: &[u8; 32], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
    let nonce = decode_fixed::<12>(&field.nonce, "Nonce")?;
    let ciphertext = decode_vec(&field.ciphertext, "Şifreli veri")?;

    password_encryption::decrypt_password(&ciphertext, &nonce, dek, aad)
}

pub(crate) fn wrap_for(key: &[u8; 32], public_key: &PublicKey) -> Result<WrappedKeyDto, String> {
    let wrapped = key_wrap::wrap_dek(key, public_key)?;

    Ok(WrappedKeyDto {
        ephemeral_public_key: BASE64.encode(wrapped.ephemeral_public_key),
        nonce: BASE64.encode(wrapped.nonce),
        ciphertext: BASE64.encode(wrapped.ciphertext),
    })
}

/// Paketlenmiş 32 baytlık bir anahtarı (DEK ya da departman özel anahtarı)
/// verilen özel anahtarla açar.
pub(crate) fn unwrap_key(
    private_key: &StaticSecret,
    access: &WrappedKeyDto,
) -> Result<Zeroizing<[u8; 32]>, String> {
    let wrapped = WrappedKey {
        ephemeral_public_key: decode_fixed::<32>(&access.ephemeral_public_key, "Geçici açık anahtar")?,
        nonce: decode_fixed::<12>(&access.nonce, "Anahtar nonce")?,
        ciphertext: decode_vec(&access.ciphertext, "Paketlenmiş anahtar")?,
    };

    key_wrap::unwrap_dek(&wrapped, private_key)
}

fn unwrap_item_dek(
    identity: &IdentityKeyPair,
    item: &EncryptedItem,
) -> Result<Zeroizing<[u8; 32]>, String> {
    let failed = |_| "Kaydın anahtarı bu hesabın kimlik anahtarıyla açılamadı.".to_string();

    match &item.access {
        ItemAccess::Direct { access } => unwrap_key(&identity.private_secret(), access).map_err(failed),
        ItemAccess::Department {
            department_key,
            item_key,
        } => {
            let department_private = unwrap_key(&identity.private_secret(), department_key)
                .map_err(|_| "Departman anahtarı bu hesabın kimlik anahtarıyla açılamadı.".to_string())?;

            unwrap_key(&StaticSecret::from(*department_private), item_key).map_err(failed)
        }
    }
}

fn validate_metadata(metadata: &ItemMetadata) -> Result<(), String> {
    if metadata.title.trim().is_empty() {
        return Err("Parola başlığı boş olamaz.".to_string());
    }

    if metadata.title.chars().count() > MAX_TITLE_CHARS {
        return Err(format!("Başlık en fazla {MAX_TITLE_CHARS} karakter olabilir."));
    }

    if metadata
        .username
        .as_ref()
        .is_some_and(|username| username.chars().count() > MAX_USERNAME_CHARS)
    {
        return Err(format!(
            "Kullanıcı adı en fazla {MAX_USERNAME_CHARS} karakter olabilir."
        ));
    }

    Ok(())
}

fn validate_secret(secret: &[u8]) -> Result<(), String> {
    if secret.is_empty() {
        return Err("Parola boş olamaz.".to_string());
    }

    if secret.len() > MAX_SECRET_BYTES {
        return Err("Parola çok uzun.".to_string());
    }

    Ok(())
}

fn require_owner(owner_id: &str, item: &EncryptedItem) -> Result<(), String> {
    if item.owner_id != owner_id {
        return Err("Bu işlem yalnızca parolanın sahibi tarafından yapılabilir.".to_string());
    }

    Ok(())
}

pub fn encrypt_new_item(
    identity: &IdentityKeyPair,
    owner_id: &str,
    title: &str,
    username: Option<&str>,
    secret: &[u8],
) -> Result<NewItem, String> {
    let metadata = ItemMetadata {
        title: title.trim().to_string(),
        username: username
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string),
    };

    validate_metadata(&metadata)?;
    validate_secret(secret)?;

    let item_id = new_item_id();
    let dek = password_encryption::generate_dek();

    let metadata_json = Zeroizing::new(
        serde_json::to_vec(&metadata).map_err(|error| error.to_string())?,
    );

    Ok(NewItem {
        metadata: seal(&metadata_json, &dek, &metadata_aad(owner_id, &item_id))?,
        secret: seal(secret, &dek, &secret_aad(owner_id, &item_id))?,
        owner_access: wrap_for(&dek, &identity.public_key())?,
        item_id,
    })
}

pub fn decrypt_metadata(
    identity: &IdentityKeyPair,
    item: &EncryptedItem,
) -> Result<ItemMetadata, String> {
    let dek = unwrap_item_dek(identity, item)?;
    let plaintext = open(&item.metadata, &dek, &metadata_aad(&item.owner_id, &item.item_id))?;

    serde_json::from_slice(&plaintext)
        .map_err(|_| "Kaydın meta verisi okunamadı.".to_string())
}

/// Geçmiş kayıtlarını çözer; en yenisi önce. Parolalar dönmez, yalnızca
/// her halden sonra neyin değiştiği.
pub fn history_summary(
    identity: &IdentityKeyPair,
    item: &EncryptedItem,
    records: &[HistoryRecord],
) -> Result<Vec<HistoryInfo>, String> {
    if records.is_empty() {
        return Ok(Vec::new());
    }

    let dek = unwrap_item_dek(identity, item)?;
    let aad = history_aad(&item.owner_id, &item.item_id);

    let mut entries = records
        .iter()
        .map(|record| {
            let id = record
                .id
                .clone()
                .ok_or_else(|| "Geçmiş kaydının kimliği eksik.".to_string())?;
            Ok((id, open_history_entry(record, &dek, &aad)?))
        })
        .collect::<Result<Vec<_>, String>>()?;
    entries.sort_by_key(|(_, entry)| entry.replaced_at);

    let metadata: ItemMetadata = serde_json::from_slice(&open(
        &item.metadata,
        &dek,
        &metadata_aad(&item.owner_id, &item.item_id),
    )?)
    .map_err(|_| "Kaydın meta verisi okunamadı.".to_string())?;
    let secret = open(&item.secret, &dek, &secret_aad(&item.owner_id, &item.item_id))?;
    let current_password = Zeroizing::new(BASE64.encode(secret.as_slice()));

    let mut result = Vec::with_capacity(entries.len());

    for (position, (id, entry)) in entries.iter().enumerate() {
        let (next_title, next_username, next_password) = match entries.get(position + 1) {
            Some((_, next)) => (&next.title, &next.username, &next.password),
            None => (&metadata.title, &metadata.username, &*current_password),
        };

        result.push(HistoryInfo {
            id: id.clone(),
            replaced_at: entry.replaced_at,
            title: entry.title.clone(),
            username: entry.username.clone(),
            title_changed: &entry.title != next_title,
            username_changed: &entry.username != next_username,
            password_changed: &entry.password != next_password,
        });
    }

    result.reverse();
    Ok(result)
}

pub fn decrypt_secret(
    identity: &IdentityKeyPair,
    item: &EncryptedItem,
) -> Result<Zeroizing<Vec<u8>>, String> {
    let dek = unwrap_item_dek(identity, item)?;

    open(&item.secret, &dek, &secret_aad(&item.owner_id, &item.item_id))
}

/// Çağıranın DEK'ini çözer ve alıcının açık anahtarına paketler.
///
/// Kimin erişim alabileceğine sunucudaki paylaşım kuralları karar verir;
/// kayda erişimi olan her istemci, kurala göre erişimi olması gereken
/// fakat anahtarı eksik olan kullanıcılar için paket üretebilir.
pub fn wrap_for_recipient(
    identity: &IdentityKeyPair,
    item: &EncryptedItem,
    recipient_public_key: &str,
) -> Result<WrappedKeyDto, String> {
    let dek = unwrap_item_dek(identity, item)?;

    // Kaydın gerçekten bu DEK ile şifrelendiğini doğrula; aksi halde alıcıya
    // işe yaramayan bir anahtar verilmiş olur.
    open(&item.metadata, &dek, &metadata_aad(&item.owner_id, &item.item_id))?;

    wrap_for(&dek, &decode_public_key(recipient_public_key)?)
}

/// Kaydı yeni bir DEK ile yeniden şifreler ve yalnızca `recipients`,
/// `departments` ile sahibin kendisi için yeni anahtar paketleri üretir.
/// Listede olmayanların elindeki eski DEK yeni veriyi açamaz.
pub fn rekey(
    identity: &IdentityKeyPair,
    owner_id: &str,
    item: &EncryptedItem,
    history: &[HistoryRecord],
    recipients: &[Recipient],
    departments: &[DepartmentRecipient],
) -> Result<RekeyedItem, String> {
    reencrypt(identity, owner_id, item, history, recipients, departments, None)
}

/// Kayıtta yapılacak değişiklik. `password` boşsa mevcut parola korunur.
pub struct ItemChanges<'a> {
    pub title: &'a str,
    pub username: Option<&'a str>,
    pub password: Option<&'a [u8]>,
}

/// Kaydı yeni içerikle ve yeni bir DEK ile yeniden şifreler. Her düzenleme
/// aynı zamanda bir rekey'dir: daha önce erişimi kaldırılmış birinin elindeki
/// eski DEK yeni parolayı açamaz.
pub fn edit(
    identity: &IdentityKeyPair,
    owner_id: &str,
    item: &EncryptedItem,
    history: &[HistoryRecord],
    recipients: &[Recipient],
    departments: &[DepartmentRecipient],
    changes: &ItemChanges,
) -> Result<RekeyedItem, String> {
    reencrypt(identity, owner_id, item, history, recipients, departments, Some(changes))
}

fn reencrypt(
    identity: &IdentityKeyPair,
    owner_id: &str,
    item: &EncryptedItem,
    history: &[HistoryRecord],
    recipients: &[Recipient],
    departments: &[DepartmentRecipient],
    changes: Option<&ItemChanges>,
) -> Result<RekeyedItem, String> {
    require_owner(owner_id, item)?;

    let old_dek = unwrap_item_dek(identity, item)?;
    let metadata_aad = metadata_aad(&item.owner_id, &item.item_id);
    let secret_aad = secret_aad(&item.owner_id, &item.item_id);

    let history_aad = history_aad(&item.owner_id, &item.item_id);

    let mut metadata = open(&item.metadata, &old_dek, &metadata_aad)?;
    let mut secret = open(&item.secret, &old_dek, &secret_aad)?;

    // Mevcut geçmiş kayıtları eski DEK ile açılır; açılamayan varsa rekey
    // yapılmaz (aksi halde geçmiş kaybolurdu).
    let mut history_plain = Vec::with_capacity(history.len() + 1);
    for record in history {
        let id = record
            .id
            .clone()
            .ok_or_else(|| "Geçmiş kaydının kimliği eksik.".to_string())?;
        let plaintext = open(&record.entry, &old_dek, &history_aad)
            .map_err(|_| "Parola geçmişi çözülemedi.".to_string())?;
        history_plain.push((Some(id), plaintext));
    }

    if let Some(changes) = changes {
        let previous: ItemMetadata = serde_json::from_slice(&metadata)
            .map_err(|_| "Kaydın meta verisi okunamadı.".to_string())?;
        let updated = ItemMetadata {
            title: changes.title.trim().to_string(),
            username: changes
                .username
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string),
        };

        validate_metadata(&updated)?;

        let new_secret = match changes.password {
            Some(password) => {
                validate_secret(password)?;
                Zeroizing::new(password.to_vec())
            }
            None => secret.clone(),
        };

        // Herhangi bir değişiklikte önceki hal geçmişe eklenir.
        if updated != previous || new_secret.as_slice() != secret.as_slice() {
            let entry = HistoryEntry {
                title: previous.title.clone(),
                username: previous.username.clone(),
                password: BASE64.encode(secret.as_slice()),
                replaced_at: now_ms(),
            };
            history_plain.push((
                None,
                Zeroizing::new(serde_json::to_vec(&entry).map_err(|error| error.to_string())?),
            ));
        }

        metadata = Zeroizing::new(serde_json::to_vec(&updated).map_err(|error| error.to_string())?);
        secret = new_secret;
    }

    let new_dek = password_encryption::generate_dek();

    let mut accesses = vec![RecipientAccess {
        user_id: owner_id.to_string(),
        access: wrap_for(&new_dek, &identity.public_key())?,
    }];

    for recipient in recipients {
        if recipient.user_id == owner_id
            || accesses.iter().any(|existing| existing.user_id == recipient.user_id)
        {
            continue;
        }

        accesses.push(RecipientAccess {
            user_id: recipient.user_id.clone(),
            access: wrap_for(&new_dek, &decode_public_key(&recipient.public_key)?)?,
        });
    }

    let department_accesses = departments
        .iter()
        .map(|department| {
            Ok(DepartmentAccess {
                department_id: department.department_id.clone(),
                key_version: department.key_version,
                access: wrap_for(&new_dek, &decode_public_key(&department.public_key)?)?,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;

    Ok(RekeyedItem {
        metadata: seal(&metadata, &new_dek, &metadata_aad)?,
        secret: seal(&secret, &new_dek, &secret_aad)?,
        history: history_plain
            .iter()
            .map(|(id, plaintext)| {
                Ok(HistoryRecord {
                    id: id.clone(),
                    entry: seal(plaintext, &new_dek, &history_aad)?,
                })
            })
            .collect::<Result<Vec<_>, String>>()?,
        accesses,
        department_accesses,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stored(new_item: &NewItem, owner_id: &str, access: WrappedKeyDto) -> EncryptedItem {
        EncryptedItem {
            item_id: new_item.item_id.clone(),
            owner_id: owner_id.to_string(),
            metadata: new_item.metadata.clone(),
            secret: new_item.secret.clone(),
            access: ItemAccess::Direct { access },
        }
    }

    #[test]
    fn owner_can_decrypt_own_item() {
        let owner = IdentityKeyPair::generate();
        let new_item =
            encrypt_new_item(&owner, "owner", " Mail ", Some("ali@x.com"), b"s3cret").unwrap();
        let item = stored(&new_item, "owner", new_item.owner_access.clone());

        assert_eq!(
            decrypt_metadata(&owner, &item).unwrap(),
            ItemMetadata {
                title: "Mail".to_string(),
                username: Some("ali@x.com".to_string()),
            }
        );
        assert_eq!(decrypt_secret(&owner, &item).unwrap().as_slice(), b"s3cret");
    }

    #[test]
    fn recipient_can_decrypt_after_grant_and_stranger_cannot() {
        let owner = IdentityKeyPair::generate();
        let recipient = IdentityKeyPair::generate();
        let stranger = IdentityKeyPair::generate();

        let new_item = encrypt_new_item(&owner, "owner", "VPN", None, b"pw").unwrap();
        let owner_item = stored(&new_item, "owner", new_item.owner_access.clone());

        let recipient_access = wrap_for_recipient(
            &owner,
            &owner_item,
            &encode_public_key(&recipient.public_key()),
        )
        .unwrap();

        let recipient_item = stored(&new_item, "owner", recipient_access);

        assert_eq!(decrypt_secret(&recipient, &recipient_item).unwrap().as_slice(), b"pw");
        assert!(decrypt_secret(&stranger, &recipient_item).is_err());
    }

    #[test]
    fn non_owner_cannot_rekey() {
        let owner = IdentityKeyPair::generate();
        let other = IdentityKeyPair::generate();

        let new_item = encrypt_new_item(&owner, "owner", "VPN", None, b"pw").unwrap();
        let item = stored(&new_item, "owner", new_item.owner_access.clone());

        assert!(rekey(&other, "other", &item, &[], &[], &[]).is_err());
    }

    #[test]
    fn recipient_can_wrap_for_another_user_but_stranger_cannot() {
        let owner = IdentityKeyPair::generate();
        let recipient = IdentityKeyPair::generate();
        let third = IdentityKeyPair::generate();
        let stranger = IdentityKeyPair::generate();

        let new_item = encrypt_new_item(&owner, "owner", "VPN", None, b"pw").unwrap();
        let owner_item = stored(&new_item, "owner", new_item.owner_access.clone());

        let recipient_item = stored(
            &new_item,
            "owner",
            wrap_for_recipient(&owner, &owner_item, &encode_public_key(&recipient.public_key()))
                .unwrap(),
        );

        let third_item = stored(
            &new_item,
            "owner",
            wrap_for_recipient(&recipient, &recipient_item, &encode_public_key(&third.public_key()))
                .unwrap(),
        );

        assert_eq!(decrypt_secret(&third, &third_item).unwrap().as_slice(), b"pw");

        // Erişimi olmayan biri, başkasının paketini kullanarak anahtar üretemez.
        assert!(
            wrap_for_recipient(&stranger, &recipient_item, &encode_public_key(&stranger.public_key()))
                .is_err()
        );
    }

    #[test]
    fn rekey_locks_out_removed_recipient() {
        let owner = IdentityKeyPair::generate();
        let kept = IdentityKeyPair::generate();
        let removed = IdentityKeyPair::generate();

        let new_item = encrypt_new_item(&owner, "owner", "DB", None, b"pw").unwrap();
        let owner_item = stored(&new_item, "owner", new_item.owner_access.clone());

        let removed_access = wrap_for_recipient(
            &owner,
            &owner_item,
            &encode_public_key(&removed.public_key()),
        )
        .unwrap();

        let rekeyed = rekey(
            &owner,
            "owner",
            &owner_item,
            &[],
            &[Recipient {
                user_id: "kept".to_string(),
                public_key: encode_public_key(&kept.public_key()),
            }],
            &[],
        )
        .unwrap();

        let user_ids: Vec<_> = rekeyed.accesses.iter().map(|a| a.user_id.as_str()).collect();
        assert_eq!(user_ids, ["owner", "kept"]);

        let after = |access: WrappedKeyDto| EncryptedItem {
            item_id: new_item.item_id.clone(),
            owner_id: "owner".to_string(),
            metadata: rekeyed.metadata.clone(),
            secret: rekeyed.secret.clone(),
            access: ItemAccess::Direct { access },
        };

        assert_eq!(
            decrypt_secret(&kept, &after(rekeyed.accesses[1].access.clone()))
                .unwrap()
                .as_slice(),
            b"pw"
        );

        // Eski paketlenmiş anahtar yeni şifreli veriyi açamaz.
        assert!(decrypt_secret(&removed, &after(removed_access)).is_err());
    }

    #[test]
    fn edit_changes_content_and_keeps_password_when_not_given() {
        let owner = IdentityKeyPair::generate();
        let recipient = IdentityKeyPair::generate();

        let new_item = encrypt_new_item(&owner, "owner", "Eski", Some("ali"), b"pw1").unwrap();
        let owner_item = stored(&new_item, "owner", new_item.owner_access.clone());
        let recipients = [Recipient {
            user_id: "r".to_string(),
            public_key: encode_public_key(&recipient.public_key()),
        }];

        let renamed = edit(
            &owner,
            "owner",
            &owner_item,
            &[],
            &recipients,
            &[],
            &ItemChanges { title: " Yeni ", username: Some(" "), password: None },
        )
        .unwrap();

        let as_recipient = EncryptedItem {
            metadata: renamed.metadata.clone(),
            secret: renamed.secret.clone(),
            access: ItemAccess::Direct { access: renamed.accesses[1].access.clone() },
            ..owner_item.clone()
        };

        assert_eq!(
            decrypt_metadata(&recipient, &as_recipient).unwrap(),
            ItemMetadata { title: "Yeni".to_string(), username: None }
        );
        assert_eq!(decrypt_secret(&recipient, &as_recipient).unwrap().as_slice(), b"pw1");

        let changed = edit(
            &owner,
            "owner",
            &owner_item,
            &[],
            &[],
            &[],
            &ItemChanges { title: "Yeni", username: None, password: Some(b"pw2") },
        )
        .unwrap();

        let as_owner = EncryptedItem {
            metadata: changed.metadata,
            secret: changed.secret,
            access: ItemAccess::Direct { access: changed.accesses[0].access.clone() },
            ..owner_item.clone()
        };
        assert_eq!(decrypt_secret(&owner, &as_owner).unwrap().as_slice(), b"pw2");
    }

    fn apply(item: &EncryptedItem, result: RekeyedItem, history: &mut Vec<HistoryRecord>) -> EncryptedItem {
        // Sunucunun yaptığı gibi yeni geçmiş kaydına kimlik verilir.
        *history = result
            .history
            .into_iter()
            .enumerate()
            .map(|(n, record)| HistoryRecord {
                id: Some(record.id.unwrap_or_else(|| format!("h{n}"))),
                entry: record.entry,
            })
            .collect();

        EncryptedItem {
            metadata: result.metadata,
            secret: result.secret,
            access: ItemAccess::Direct { access: result.accesses[0].access.clone() },
            ..item.clone()
        }
    }

    #[test]
    fn every_change_goes_to_history_readable_by_recipients() {
        let owner = IdentityKeyPair::generate();
        let recipient = IdentityKeyPair::generate();
        let removed = IdentityKeyPair::generate();
        let recipients = [Recipient {
            user_id: "r".to_string(),
            public_key: encode_public_key(&recipient.public_key()),
        }];

        let new_item = encrypt_new_item(&owner, "owner", "VPN", Some("ali"), b"pw1").unwrap();
        let mut item = stored(&new_item, "owner", new_item.owner_access.clone());
        let mut history = Vec::new();
        let removed_access =
            wrap_for_recipient(&owner, &item, &encode_public_key(&removed.public_key())).unwrap();

        // Hiçbir şey değişmezse geçmişe yazılmaz.
        let same = ItemChanges { title: "VPN", username: Some("ali"), password: Some(b"pw1") };
        let unchanged = edit(&owner, "owner", &item, &history, &recipients, &[], &same).unwrap();
        item = apply(&item, unchanged, &mut history);
        assert!(history.is_empty());

        // Yalnızca başlık değişikliği de geçmişe yazılır.
        let renamed = ItemChanges { title: "VPN 2", username: Some("ali"), password: None };
        item = apply(&item, edit(&owner, "owner", &item, &history, &recipients, &[], &renamed).unwrap(), &mut history);

        let new_password = ItemChanges { title: "VPN 2", username: None, password: Some(b"pw2") };
        item = apply(&item, edit(&owner, "owner", &item, &history, &recipients, &[], &new_password).unwrap(), &mut history);
        assert_eq!(history.len(), 2);

        // Rekey bütün geçmişi yeni DEK'e taşır.
        let rekeyed = rekey(&owner, "owner", &item, &history, &recipients, &[]).unwrap();
        let recipient_access = rekeyed.accesses[1].access.clone();
        let item = apply(&item, rekeyed, &mut history);
        let as_recipient = EncryptedItem {
            access: ItemAccess::Direct { access: recipient_access },
            ..item.clone()
        };

        let summary = history_summary(&recipient, &as_recipient, &history).unwrap();
        let shape: Vec<_> = summary
            .iter()
            .map(|e| (e.title.as_str(), e.username.as_deref(), e.title_changed, e.username_changed, e.password_changed))
            .collect();
        assert_eq!(
            shape,
            [
                ("VPN 2", Some("ali"), false, true, true),
                ("VPN", Some("ali"), true, false, false),
            ]
        );

        // Erişimi kaldırılan kişinin eski DEK'i geçmişi açamaz.
        let as_removed = EncryptedItem {
            access: ItemAccess::Direct { access: removed_access },
            ..as_recipient.clone()
        };
        assert!(history_summary(&removed, &as_removed, &history).is_err());
    }

    #[test]
    fn history_is_not_limited() {
        let owner = IdentityKeyPair::generate();
        let new_item = encrypt_new_item(&owner, "owner", "VPN", None, &[b'a'; 4000]).unwrap();
        let mut item = stored(&new_item, "owner", new_item.owner_access.clone());
        let mut history = Vec::new();

        for n in 1..=30u32 {
            let password = format!("{n:04000}");
            let changes = ItemChanges { title: "VPN", username: None, password: Some(password.as_bytes()) };
            let edited = edit(&owner, "owner", &item, &history, &[], &[], &changes).unwrap();
            item = apply(&item, edited, &mut history);
        }

        assert_eq!(history_summary(&owner, &item, &history).unwrap().len(), 30);
        assert!(history.iter().all(|record| record.entry.ciphertext.len() <= 16 * 1024));
    }

    #[test]
    fn history_from_another_item_is_rejected() {
        let owner = IdentityKeyPair::generate();
        let a = encrypt_new_item(&owner, "owner", "A", None, b"pw").unwrap();
        let b = encrypt_new_item(&owner, "owner", "B", None, b"pw").unwrap();
        let item_a = stored(&a, "owner", a.owner_access.clone());
        let item_b = stored(&b, "owner", b.owner_access.clone());

        let mut history = Vec::new();
        let changes = ItemChanges { title: "A2", username: None, password: None };
        apply(&item_a, edit(&owner, "owner", &item_a, &[], &[], &[], &changes).unwrap(), &mut history);

        // Rekey, açılamayan bir geçmiş kaydıyla yapılmaz (geçmiş kaybolmasın).
        assert!(rekey(&owner, "owner", &item_b, &history, &[], &[]).is_err());
    }

    #[test]
    fn edit_is_owner_only_and_validated() {
        let owner = IdentityKeyPair::generate();
        let new_item = encrypt_new_item(&owner, "owner", "A", None, b"pw").unwrap();
        let item = stored(&new_item, "owner", new_item.owner_access.clone());

        let changes = ItemChanges { title: "B", username: None, password: None };
        assert!(edit(&owner, "other", &item, &[], &[], &[], &changes).is_err());

        let empty_title = ItemChanges { title: " ", username: None, password: None };
        assert!(edit(&owner, "owner", &item, &[], &[], &[], &empty_title).is_err());

        let empty_password = ItemChanges { title: "B", username: None, password: Some(b"") };
        assert!(edit(&owner, "owner", &item, &[], &[], &[], &empty_password).is_err());
    }

    #[test]
    fn department_member_decrypts_through_the_department_key() {
        let owner = IdentityKeyPair::generate();
        let department = IdentityKeyPair::generate();
        let member = IdentityKeyPair::generate();

        let new_item = encrypt_new_item(&owner, "owner", "VPN", None, b"pw").unwrap();
        let owner_item = stored(&new_item, "owner", new_item.owner_access.clone());

        let item_key =
            wrap_for_recipient(&owner, &owner_item, &encode_public_key(&department.public_key()))
                .unwrap();
        let department_key = wrap_for(department.private_key(), &member.public_key()).unwrap();

        let member_item = EncryptedItem {
            access: ItemAccess::Department {
                department_key,
                item_key,
            },
            ..owner_item.clone()
        };

        assert_eq!(decrypt_secret(&member, &member_item).unwrap().as_slice(), b"pw");
        assert!(decrypt_secret(&IdentityKeyPair::generate(), &member_item).is_err());
    }

    #[test]
    fn rekey_wraps_the_new_key_for_departments() {
        let owner = IdentityKeyPair::generate();
        let department = IdentityKeyPair::generate();

        let new_item = encrypt_new_item(&owner, "owner", "VPN", None, b"pw").unwrap();
        let owner_item = stored(&new_item, "owner", new_item.owner_access.clone());

        let rekeyed = rekey(
            &owner,
            "owner",
            &owner_item,
            &[],
            &[],
            &[DepartmentRecipient {
                department_id: "d1".to_string(),
                key_version: 3,
                public_key: encode_public_key(&department.public_key()),
            }],
        )
        .unwrap();

        assert_eq!(rekeyed.department_accesses.len(), 1);
        assert_eq!(rekeyed.department_accesses[0].key_version, 3);

        let dek = unwrap_key(&department.private_secret(), &rekeyed.department_accesses[0].access)
            .unwrap();
        let plaintext = open(&rekeyed.secret, &dek, &secret_aad("owner", &new_item.item_id)).unwrap();
        assert_eq!(plaintext.as_slice(), b"pw");
    }

    #[test]
    fn ciphertext_moved_to_another_item_is_rejected() {
        let owner = IdentityKeyPair::generate();
        let first = encrypt_new_item(&owner, "owner", "A", None, b"a").unwrap();
        let second = encrypt_new_item(&owner, "owner", "B", None, b"b").unwrap();

        let mut swapped = stored(&second, "owner", first.owner_access.clone());
        swapped.metadata = first.metadata.clone();
        swapped.secret = first.secret.clone();

        assert!(decrypt_secret(&owner, &swapped).is_err());
    }

    #[test]
    fn empty_title_and_secret_are_rejected() {
        let owner = IdentityKeyPair::generate();

        assert!(encrypt_new_item(&owner, "owner", "  ", None, b"pw").is_err());
        assert!(encrypt_new_item(&owner, "owner", "T", None, b"").is_err());
    }
}
