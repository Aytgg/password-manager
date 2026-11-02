//! Departman anahtarları.
//!
//! Her departmanın bir X25519 anahtar çifti vardır. Departmanla paylaşılan
//! kayıtların DEK'i departmanın açık anahtarına paketlenir; departmanın özel
//! anahtarı da departman üyelerine ve yöneticilere paketlenir. Böylece yeni
//! bir üyeye tek bir paket vermek departmanın bütün kayıtlarını açar ve
//! kaydın sahibinin çevrimiçi olması gerekmez.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::identity::IdentityKeyPair;
use crate::vault::items::{
    decode_public_key, encode_public_key, unwrap_key, wrap_for, Recipient, RecipientAccess,
    WrappedKeyDto,
};

/// Çağırana paketlenmiş departman özel anahtarı ve departmanın sunucudaki
/// açık anahtarı.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DepartmentKeyRef {
    pub public_key: String,
    pub access: WrappedKeyDto,
}

/// Bir kaydın departman açık anahtarına paketlenmiş DEK'i.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DepartmentItemKey {
    pub item: String,
    pub access: WrappedKeyDto,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NewDepartmentKey {
    pub public_key: String,
    pub accesses: Vec<RecipientAccess>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RotatedDepartmentKey {
    pub public_key: String,
    pub accesses: Vec<RecipientAccess>,
    pub item_keys: Vec<DepartmentItemKey>,
}

fn wrap_for_holders(
    department: &IdentityKeyPair,
    holders: &[Recipient],
) -> Result<Vec<RecipientAccess>, String> {
    holders
        .iter()
        .map(|holder| {
            Ok(RecipientAccess {
                user_id: holder.user_id.clone(),
                access: wrap_for(department.private_key(), &decode_public_key(&holder.public_key)?)?,
            })
        })
        .collect()
}

/// Departman anahtarını açar ve sunucunun bildirdiği açık anahtarla
/// eşleştiğini doğrular; aksi halde üyelere yanlış anahtar dağıtılırdı.
fn open_department_key(
    identity: &IdentityKeyPair,
    key: &DepartmentKeyRef,
) -> Result<IdentityKeyPair, String> {
    let private_key: Zeroizing<[u8; 32]> = unwrap_key(&identity.private_secret(), &key.access)
        .map_err(|_| "Departman anahtarı bu hesabın kimlik anahtarıyla açılamadı.".to_string())?;

    let department = IdentityKeyPair::from_private_key(*private_key);

    if encode_public_key(&department.public_key()) != key.public_key {
        return Err("Departman anahtarı sunucudaki açık anahtarla eşleşmiyor.".to_string());
    }

    Ok(department)
}

pub fn create_department_key(holders: &[Recipient]) -> Result<NewDepartmentKey, String> {
    let department = IdentityKeyPair::generate();

    Ok(NewDepartmentKey {
        public_key: encode_public_key(&department.public_key()),
        accesses: wrap_for_holders(&department, holders)?,
    })
}

pub fn wrap_department_key(
    identity: &IdentityKeyPair,
    key: &DepartmentKeyRef,
    recipients: &[Recipient],
) -> Result<Vec<RecipientAccess>, String> {
    wrap_for_holders(&open_department_key(identity, key)?, recipients)
}

/// Yeni bir departman anahtarı üretir, kalan anahtar sahiplerine dağıtır ve
/// departmana paketlenmiş kayıt anahtarlarını yeni anahtara taşır. Çıkarılan
/// üyenin elindeki eski anahtar yeni paketleri açamaz.
pub fn rotate_department_key(
    identity: &IdentityKeyPair,
    key: &DepartmentKeyRef,
    holders: &[Recipient],
    item_keys: &[DepartmentItemKey],
) -> Result<RotatedDepartmentKey, String> {
    let current = open_department_key(identity, key)?;
    let next = IdentityKeyPair::generate();

    let item_keys = item_keys
        .iter()
        .map(|item_key| {
            let dek = unwrap_key(&current.private_secret(), &item_key.access)
                .map_err(|_| "Departmandaki bir kaydın anahtarı açılamadı.".to_string())?;

            Ok(DepartmentItemKey {
                item: item_key.item.clone(),
                access: wrap_for(&dek, &next.public_key())?,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;

    Ok(RotatedDepartmentKey {
        public_key: encode_public_key(&next.public_key()),
        accesses: wrap_for_holders(&next, holders)?,
        item_keys,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recipient(id: &str, identity: &IdentityKeyPair) -> Recipient {
        Recipient {
            user_id: id.to_string(),
            public_key: encode_public_key(&identity.public_key()),
        }
    }

    fn key_ref(public_key: &str, accesses: &[RecipientAccess], user_id: &str) -> DepartmentKeyRef {
        DepartmentKeyRef {
            public_key: public_key.to_string(),
            access: accesses
                .iter()
                .find(|access| access.user_id == user_id)
                .unwrap()
                .access
                .clone(),
        }
    }

    #[test]
    fn holder_can_share_the_department_key_with_a_new_member() {
        let admin = IdentityKeyPair::generate();
        let member = IdentityKeyPair::generate();

        let created = create_department_key(&[recipient("admin", &admin)]).unwrap();
        let admin_key = key_ref(&created.public_key, &created.accesses, "admin");

        let shared = wrap_department_key(&admin, &admin_key, &[recipient("member", &member)]).unwrap();
        let member_key = key_ref(&created.public_key, &shared, "member");

        assert!(open_department_key(&member, &member_key).is_ok());
        assert!(open_department_key(&IdentityKeyPair::generate(), &member_key).is_err());
    }

    #[test]
    fn key_not_matching_the_server_public_key_is_rejected() {
        let admin = IdentityKeyPair::generate();
        let created = create_department_key(&[recipient("admin", &admin)]).unwrap();
        let other = create_department_key(&[]).unwrap();

        let mismatched = key_ref(&other.public_key, &created.accesses, "admin");

        assert!(wrap_department_key(&admin, &mismatched, &[]).is_err());
    }

    #[test]
    fn rotation_moves_item_keys_and_locks_out_removed_member() {
        let admin = IdentityKeyPair::generate();
        let removed = IdentityKeyPair::generate();

        let created =
            create_department_key(&[recipient("admin", &admin), recipient("removed", &removed)])
                .unwrap();
        let admin_key = key_ref(&created.public_key, &created.accesses, "admin");

        let dek = [9u8; 32];
        let item_key = DepartmentItemKey {
            item: "i1".to_string(),
            access: wrap_for(&dek, &decode_public_key(&created.public_key).unwrap()).unwrap(),
        };

        let rotated =
            rotate_department_key(&admin, &admin_key, &[recipient("admin", &admin)], &[item_key])
                .unwrap();

        assert_ne!(rotated.public_key, created.public_key);
        assert_eq!(rotated.accesses.len(), 1);

        let next = open_department_key(&admin, &key_ref(&rotated.public_key, &rotated.accesses, "admin"))
            .unwrap();
        let moved = unwrap_key(&next.private_secret(), &rotated.item_keys[0].access).unwrap();
        assert_eq!(*moved, dek);

        // Çıkarılan üyenin eski departman anahtarı yeni paketi açamaz.
        let old = open_department_key(&removed, &key_ref(&created.public_key, &created.accesses, "removed"))
            .unwrap();
        assert!(unwrap_key(&old.private_secret(), &rotated.item_keys[0].access).is_err());
    }
}
