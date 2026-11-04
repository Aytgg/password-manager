pub mod crypto;
pub mod storage;
pub mod vault;
pub mod vault_reset;
pub mod clipboard;

use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use serde::Serialize;
use tauri::{Emitter, Manager};
use tauri_plugin_clipboard_manager::ClipboardExt;
use zeroize::Zeroizing;

use crate::crypto::{
    kdf::{derive_password_keys, normalize_email},
    key_encryption::{protect_master_key, unlock_master_key},
    master_key::generate_master_key,
};
use crate::storage::{
    identity_store::{
        delete_invite_identity, load_identity, load_invite_identity, load_or_create_identity,
        save_invite_identity,
    },
    key_store::PlatformKeyStore,
};
use crate::vault::{
    cache,
    key_file::{
        load_protected_master_key, replace_protected_master_key, save_protected_master_key,
    },
    departments::{
        self, DepartmentItemKey, DepartmentKeyRef, NewDepartmentKey, RotatedDepartmentKey,
    },
    invite::{self, KeyedAccess, PreparedInvite},
    owner_binding::{load_owner_binding, save_owner_binding, VaultOwner},
    items::{
        self, DepartmentRecipient, EncryptedItem, NewItem, Recipient, RecipientAccess,
        RekeyedItem, WrappedKeyDto,
    },
    paths::VaultPaths,
    session::VaultSession,
};

const CLIPBOARD_CLEAR_AFTER_SECS: u64 = 30;
const MIN_PASSWORD_CHARS: usize = 8;
const MAX_PASSWORD_BYTES: usize = 1024;

fn validate_new_password(password: &str) -> Result<(), String> {
    if password.trim().is_empty() {
        return Err("Parola boş olamaz.".to_string());
    }

    if password.chars().count() < MIN_PASSWORD_CHARS {
        return Err(format!("Parola en az {MIN_PASSWORD_CHARS} karakter olmalı."));
    }

    if password.len() > MAX_PASSWORD_BYTES {
        return Err("Parola çok uzun.".to_string());
    }

    Ok(())
}

fn remove_file_if_exists(path: &Path) -> Result<(), String> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "Dosya silinemedi ({}): {error}",
            path.display()
        )),
    }
}

fn schedule_clipboard_cleanup(
    app: tauri::AppHandle,
    expected_text: Zeroizing<String>,
) {
    let worker_app = app.clone();

    let result = std::thread::Builder::new()
        .name("password-clipboard-cleanup".to_string())
        .spawn(move || {
            std::thread::sleep(Duration::from_secs(
                CLIPBOARD_CLEAR_AFTER_SECS,
            ));

            // Clipboard read_text ana thread'de çağrılmamalıdır.
            let current_text = match worker_app.clipboard().read_text() {
                Ok(text) => Zeroizing::new(text),
                Err(error) => {
                    log::warn!(
                        "Otomatik pano temizliği için pano okunamadı: {error}"
                    );
                    return;
                }
            };

            if current_text.as_str() == expected_text.as_str()
                && let Err(error) = worker_app.clipboard().clear()
            {
                log::warn!(
                    "Pano otomatik temizlenemedi: {error}"
                );
            }
        });

    if let Err(error) = result {
        // Parola kopyalanmış olabilir fakat zamanlayıcı başlatılamamıştır.
        // Kullanıcının sonradan kopyaladığı içeriği silmemek için panoyu
        // koşulsuz temizlemiyoruz.
        log::warn!(
            "Pano temizleme zamanlayıcısı başlatılamadı: {error}"
        );
    }
}

fn app_data_dir(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_data_dir()
        .map_err(|error| error.to_string())
}

/// Kasa açıldığında arayüze dönen bilgiler. `auth_secret` yalnızca sunucu
/// girişi içindir; kasayı açmaya yetmez.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UnlockedVaultInfo {
    email: String,
    user_id: String,
    auth_secret: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PasswordChangeSecrets {
    current_auth_secret: String,
    new_auth_secret: String,
}

#[tauri::command]
fn vault_exists(app: tauri::AppHandle, email: String) -> Result<bool, String> {
    Ok(VaultPaths::for_email(&app_data_dir(&app)?, &email)?.is_initialized())
}

/// Bu cihazda kasası olmayan bir hesabın ilk sunucu girişi için.
#[tauri::command]
async fn derive_auth_secret(email: String, password: String) -> Result<String, String> {
    let password = Zeroizing::new(password);

    tauri::async_runtime::spawn_blocking(move || {
        let keys = derive_password_keys(&email, password.as_bytes())?;
        Ok(hex::encode(*keys.auth_secret))
    })
    .await
    .map_err(|error| error.to_string())?
}

/// Yöneticinin cihazında davet kodu üretir. Kod yalnızca arayüze döner;
/// sunucuya açık anahtar ve doğrulayıcı gönderilir.
#[tauri::command]
async fn prepare_invite(email: String) -> Result<PreparedInvite, String> {
    tauri::async_runtime::spawn_blocking(move || invite::prepare_invite(&email))
        .await
        .map_err(|error| error.to_string())?
}

/// Kayıt sırasında kullanıcının davet kodunu bildiğini sunucuya kanıtlar.
#[tauri::command]
async fn derive_invite_verifier(email: String, invite_code: String) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || invite::invite_verifier(&email, &invite_code))
        .await
        .map_err(|error| error.to_string())?
}

#[tauri::command]
fn current_vault(
    session: tauri::State<'_, Arc<VaultSession>>,
) -> Result<Option<VaultOwner>, String> {
    session.current_owner()
}

#[tauri::command]
fn lock_vault(
    session: tauri::State<'_, Arc<VaultSession>>,
) -> Result<(), String> {
    session.lock()
}

#[tauri::command]
fn touch_vault_activity(
    session: tauri::State<'_, Arc<VaultSession>>,
) -> Result<(), String> {
    session.record_activity()
}

/// Bu cihazda hesabın kasasını oluşturur. Sunucu girişi başarılı olduktan
/// sonra çağrılır; `user_id` sunucudaki kullanıcı kimliğidir. Davetle ilk
/// kayıtta `invite_code` verilir; koddan türetilen geçici kimlik, ona
/// paketlenmiş anahtarlar kalıcı kimliğe taşınana kadar kasada saklanır.
#[tauri::command]
async fn create_vault(
    app: tauri::AppHandle,
    session: tauri::State<'_, Arc<VaultSession>>,
    email: String,
    password: String,
    user_id: String,
    invite_code: Option<String>,
) -> Result<(), String> {
    let password = Zeroizing::new(password);
    let invite_code = invite_code.map(Zeroizing::new);
    let email = normalize_email(&email);
    let user_id = user_id.trim().to_string();

    if user_id.is_empty() {
        return Err("Sunucu kullanıcı kimliği eksik.".to_string());
    }

    let paths = VaultPaths::for_email(&app_data_dir(&app)?, &email)?;
    let session = session.inner().clone();

    tauri::async_runtime::spawn_blocking(move || {
        std::fs::create_dir_all(&paths.dir)
            .map_err(|error| error.to_string())?;

        if paths.has_any_file() && !cfg!(debug_assertions) {
            return Err(
                "Mevcut kasa dosyaları bulundu. Yayın sürümünde kasa \
                otomatik olarak silinemez."
                    .to_string(),
            );
        }

        session.lock()?;

        for path in paths.all_files() {
            remove_file_if_exists(path)?;
        }

        let result = (|| {
            let keys = derive_password_keys(&email, password.as_bytes())?;
            let master_key = generate_master_key();

            let protected_master_key = protect_master_key(&keys.kek, &master_key)?;

            let key_store =
                PlatformKeyStore::open(&paths.stronghold, &master_key)?;

            let identity =
                load_or_create_identity(&key_store, &user_id)?.identity;

            if let Some(code) = &invite_code {
                save_invite_identity(&key_store, &user_id, &invite::invite_identity(&email, code)?)?;
            }

            save_protected_master_key(
                &paths.master_key,
                &protected_master_key,
            )?;

            let owner = VaultOwner { email, user_id };

            save_owner_binding(&paths.owner_binding, &master_key, &owner)?;

            session.unlock(identity, key_store, owner, cache::derive_cache_key(&master_key)?)?;

            Ok::<(), String>(())
        })();

        if result.is_err() {
            for path in paths.all_files() {
                let _ = remove_file_if_exists(path);
            }
        }

        result
    })
    .await
    .map_err(|error| error.to_string())?
}

/// Yerel kasayı açar. İnternet gerektirmez; dönen `auth_secret` bağlantı
/// olduğunda sunucuya giriş için kullanılır.
#[tauri::command]
async fn unlock_vault(
    app: tauri::AppHandle,
    session: tauri::State<'_, Arc<VaultSession>>,
    email: String,
    password: String,
) -> Result<UnlockedVaultInfo, String> {
    let password = Zeroizing::new(password);
    let email = normalize_email(&email);

    if password.is_empty() {
        return Err("Parola boş olamaz.".to_string());
    }

    let paths = VaultPaths::for_email(&app_data_dir(&app)?, &email)?;
    let session = session.inner().clone();

    tauri::async_runtime::spawn_blocking(move || {
        if !paths.is_complete() {
            return Err(
                "Kasa dosyalarından biri eksik. Kasa açılamadı."
                    .to_string(),
            );
        }

        let keys = derive_password_keys(&email, password.as_bytes())?;

        let protected_master_key =
            load_protected_master_key(&paths.master_key)?;

        let master_key = unlock_master_key(&keys.kek, &protected_master_key)
            .map_err(|_| "E-posta ya da parola yanlış.".to_string())?;

        let owner = load_owner_binding(&paths.owner_binding, &master_key, &email)?;

        let key_store =
            PlatformKeyStore::open(&paths.stronghold, &master_key)?;

        let identity = load_identity(&key_store, &owner.user_id)?;

        let info = UnlockedVaultInfo {
            email: owner.email.clone(),
            user_id: owner.user_id.clone(),
            auth_secret: hex::encode(*keys.auth_secret),
        };

        session.unlock(identity, key_store, owner, cache::derive_cache_key(&master_key)?)?;

        Ok(info)
    })
    .await
    .map_err(|error| error.to_string())?
}

/// Parola değişikliğinin ilk adımı: mevcut parolayı doğrular, yeni parolayla
/// korunan ana anahtarı bellekte hazırlar ve sunucu için iki giriş anahtarını
/// döndürür. Sunucu değişikliği onaylayınca `commit_password_change` çağrılır.
/// Ana anahtar değişmediği için Stronghold ve kimlik anahtarı etkilenmez.
#[tauri::command]
async fn prepare_password_change(
    app: tauri::AppHandle,
    session: tauri::State<'_, Arc<VaultSession>>,
    current_password: String,
    new_password: String,
) -> Result<PasswordChangeSecrets, String> {
    let current_password = Zeroizing::new(current_password);
    let new_password = Zeroizing::new(new_password);

    if current_password.is_empty() {
        return Err("Mevcut parolayı gir.".to_string());
    }

    validate_new_password(&new_password)?;

    if *current_password == *new_password {
        return Err("Yeni parola mevcut paroladan farklı olmalı.".to_string());
    }

    let owner = session
        .current_owner()?
        .ok_or_else(|| "Kasa kilitli.".to_string())?;
    let paths = VaultPaths::for_email(&app_data_dir(&app)?, &owner.email)?;
    let session = session.inner().clone();

    tauri::async_runtime::spawn_blocking(move || {
        let current = derive_password_keys(&owner.email, current_password.as_bytes())?;
        let protected_master_key = load_protected_master_key(&paths.master_key)?;

        let master_key = unlock_master_key(&current.kek, &protected_master_key)
            .map_err(|_| "Mevcut parola yanlış.".to_string())?;

        let next = derive_password_keys(&owner.email, new_password.as_bytes())?;

        session.set_pending_master_key(protect_master_key(&next.kek, &master_key)?)?;

        Ok(PasswordChangeSecrets {
            current_auth_secret: hex::encode(*current.auth_secret),
            new_auth_secret: hex::encode(*next.auth_secret),
        })
    })
    .await
    .map_err(|error| error.to_string())?
}

#[tauri::command]
fn commit_password_change(
    app: tauri::AppHandle,
    session: tauri::State<'_, Arc<VaultSession>>,
) -> Result<(), String> {
    let (owner, protected) = session.take_pending_master_key()?;
    let paths = VaultPaths::for_email(&app_data_dir(&app)?, &owner.email)?;

    replace_protected_master_key(&paths.master_key, &protected)
}

fn items_cache_path(app: &tauri::AppHandle, email: &str) -> Result<PathBuf, String> {
    Ok(VaultPaths::for_email(&app_data_dir(app)?, email)?.items_cache)
}

/// Yerel kayıt önbelleği; içeriği arayüz belirler. Çevrimdışı açılışta liste
/// buradan gelir.
#[tauri::command]
fn load_items_cache(
    app: tauri::AppHandle,
    session: tauri::State<'_, Arc<VaultSession>>,
) -> Result<Option<serde_json::Value>, String> {
    session.with_cache_key(|owner, key| {
        cache::load_cache(&items_cache_path(&app, &owner.email)?, key, &owner.user_id)
    })
}

#[tauri::command]
fn save_items_cache(
    app: tauri::AppHandle,
    session: tauri::State<'_, Arc<VaultSession>>,
    content: serde_json::Value,
) -> Result<(), String> {
    session.with_cache_key(|owner, key| {
        cache::save_cache(&items_cache_path(&app, &owner.email)?, key, &owner.user_id, &content)
    })
}

/// Bu hesabın X25519 açık anahtarı (base64). Convex'teki kullanıcı kaydına
/// yazılır; diğer kullanıcılar paylaşım yaparken bu anahtara paketler.
#[tauri::command]
fn get_identity_public_key(
    session: tauri::State<'_, Arc<VaultSession>>,
) -> Result<String, String> {
    session.with_identity(|identity, _| {
        Ok(items::encode_public_key(&identity.public_key()))
    })
}

#[tauri::command]
fn encrypt_new_item(
    session: tauri::State<'_, Arc<VaultSession>>,
    title: String,
    username: Option<String>,
    password: String,
) -> Result<NewItem, String> {
    let password = Zeroizing::new(password);

    session.with_identity(|identity, owner| {
        items::encrypt_new_item(
            identity,
            &owner.user_id,
            &title,
            username.as_deref(),
            password.as_bytes(),
        )
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DecryptedItemMetadata {
    item_id: String,
    title: Option<String>,
    username: Option<String>,
    error: Option<String>,
}

/// Liste için yalnızca meta veriyi çözer; parolaların kendisi çözülmez.
/// Bir kaydın çözülememesi listenin geri kalanını engellemez.
#[tauri::command]
fn decrypt_items_metadata(
    session: tauri::State<'_, Arc<VaultSession>>,
    items: Vec<EncryptedItem>,
) -> Result<Vec<DecryptedItemMetadata>, String> {
    session.with_identity(|identity, _| {
        Ok(items
            .iter()
            .map(|item| match items::decrypt_metadata(identity, item) {
                Ok(metadata) => DecryptedItemMetadata {
                    item_id: item.item_id.clone(),
                    title: Some(metadata.title),
                    username: metadata.username,
                    error: None,
                },
                Err(error) => DecryptedItemMetadata {
                    item_id: item.item_id.clone(),
                    title: None,
                    username: None,
                    error: Some(error),
                },
            })
            .collect())
    })
}

/// Parolayı Rust tarafında çözer ve doğrudan sistem panosuna yazar.
/// Açık parola React'e döndürülmez.
#[tauri::command]
fn copy_item_password_to_clipboard(
    app: tauri::AppHandle,
    session: tauri::State<'_, Arc<VaultSession>>,
    item: EncryptedItem,
) -> Result<(), String> {
    let plaintext_bytes = session.with_identity(|identity, _| {
        items::decrypt_secret(identity, &item)
    })?;

    copy_secret_to_clipboard(app, plaintext_bytes)
}

/// Parolanın eski değerlerinin değiştirilme zamanları (en yenisi önce).
/// Eski parolalar çözülmez.
#[tauri::command]
fn item_password_history(
    session: tauri::State<'_, Arc<VaultSession>>,
    item: EncryptedItem,
) -> Result<Vec<items::HistoryInfo>, String> {
    session.with_identity(|identity, _| items::history_summary(identity, &item))
}

/// Geçmişteki bir parolayı Rust tarafında çözer ve panoya yazar.
#[tauri::command]
fn copy_item_history_password_to_clipboard(
    app: tauri::AppHandle,
    session: tauri::State<'_, Arc<VaultSession>>,
    item: EncryptedItem,
    index: usize,
) -> Result<(), String> {
    let plaintext_bytes = session.with_identity(|identity, _| {
        items::decrypt_history_password(identity, &item, index)
    })?;

    copy_secret_to_clipboard(app, plaintext_bytes)
}

fn copy_secret_to_clipboard(
    app: tauri::AppHandle,
    plaintext_bytes: Zeroizing<Vec<u8>>,
) -> Result<(), String> {
    let plaintext_str = std::str::from_utf8(plaintext_bytes.as_slice())
        .map_err(|_| "Parola geçerli UTF-8 metni değil.".to_string())?;

    let plaintext = Zeroizing::new(plaintext_str.to_owned());
    drop(plaintext_bytes);

    crate::clipboard::write_sensitive_text(&app, plaintext.as_str())?;

    schedule_clipboard_cleanup(app, plaintext);

    Ok(())
}

#[tauri::command]
fn wrap_item_key_for_recipient(
    session: tauri::State<'_, Arc<VaultSession>>,
    item: EncryptedItem,
    recipient_public_key: String,
) -> Result<WrappedKeyDto, String> {
    session.with_identity(|identity, _| {
        items::wrap_for_recipient(identity, &item, &recipient_public_key)
    })
}

#[tauri::command]
fn rekey_item(
    session: tauri::State<'_, Arc<VaultSession>>,
    item: EncryptedItem,
    recipients: Vec<Recipient>,
    department_recipients: Vec<DepartmentRecipient>,
) -> Result<RekeyedItem, String> {
    session.with_identity(|identity, owner| {
        items::rekey(identity, &owner.user_id, &item, &recipients, &department_recipients)
    })
}

/// Kaydı yeni içerikle yeniden şifreler. `password` verilmezse mevcut parola
/// korunur. Açık parola Rust'a girer, React'e geri dönmez.
#[tauri::command]
fn edit_item(
    session: tauri::State<'_, Arc<VaultSession>>,
    item: EncryptedItem,
    recipients: Vec<Recipient>,
    department_recipients: Vec<DepartmentRecipient>,
    title: String,
    username: Option<String>,
    password: Option<String>,
) -> Result<RekeyedItem, String> {
    let password = password.filter(|value| !value.is_empty()).map(Zeroizing::new);

    session.with_identity(|identity, owner| {
        items::edit(
            identity,
            &owner.user_id,
            &item,
            &recipients,
            &department_recipients,
            &items::ItemChanges {
                title: &title,
                username: username.as_deref(),
                password: password.as_ref().map(|value| value.as_bytes()),
            },
        )
    })
}

#[tauri::command]
fn create_department_key(holders: Vec<Recipient>) -> Result<NewDepartmentKey, String> {
    departments::create_department_key(&holders)
}

#[tauri::command]
fn wrap_department_key(
    session: tauri::State<'_, Arc<VaultSession>>,
    key: DepartmentKeyRef,
    recipients: Vec<Recipient>,
) -> Result<Vec<RecipientAccess>, String> {
    session.with_identity(|identity, _| {
        departments::wrap_department_key(identity, &key, &recipients)
    })
}

#[tauri::command]
fn rotate_department_key(
    session: tauri::State<'_, Arc<VaultSession>>,
    key: DepartmentKeyRef,
    holders: Vec<Recipient>,
    item_keys: Vec<DepartmentItemKey>,
) -> Result<RotatedDepartmentKey, String> {
    session.with_identity(|identity, _| {
        departments::rotate_department_key(identity, &key, &holders, &item_keys)
    })
}

/// Kayıttan sonra davet anahtarına paketlenmiş anahtarlar henüz kalıcı
/// kimliğe taşınmadıysa geçici kimliğin açık anahtarı.
#[tauri::command]
fn pending_invite_key(
    session: tauri::State<'_, Arc<VaultSession>>,
) -> Result<Option<String>, String> {
    session.with_vault(|_, owner, key_store| {
        Ok(load_invite_identity(key_store, &owner.user_id)?
            .map(|identity| items::encode_public_key(&identity.public_key())))
    })
}

#[tauri::command]
fn rewrap_invite_keys(
    session: tauri::State<'_, Arc<VaultSession>>,
    keys: Vec<KeyedAccess>,
) -> Result<Vec<KeyedAccess>, String> {
    session.with_vault(|identity, owner, key_store| {
        let provisional = load_invite_identity(key_store, &owner.user_id)?
            .ok_or_else(|| "Taşınacak davet anahtarı yok.".to_string())?;

        invite::rewrap(&provisional, identity, &keys)
    })
}

/// Sunucu taşımayı onayladıktan sonra geçici kimlik silinir.
#[tauri::command]
fn finish_invite_rotation(session: tauri::State<'_, Arc<VaultSession>>) -> Result<(), String> {
    session.with_vault(|_, owner, key_store| delete_invite_identity(key_store, &owner.user_id))
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_clipboard_manager::init())
        .manage(Arc::new(VaultSession::new()))
        .setup(|app| {
            let app_data_dir = app.path().app_data_dir()?;
            std::fs::create_dir_all(&app_data_dir)?;

            let idle_session = {
                let state = app.state::<Arc<VaultSession>>();
                Arc::clone(state.inner())
            };

            let app_handle = app.handle().clone();

            std::thread::Builder::new()
                .name("vault-idle-lock".to_string())
                .spawn(move || loop {
                    std::thread::sleep(Duration::from_secs(5));

                    match idle_session.lock_if_idle() {
                        Ok(true) => {
                            let _ = app_handle.emit(
                                "vault://auto-locked",
                                (),
                            );
                        }
                        Ok(false) => {}
                        Err(error) => {
                            log::error!(
                                "Vault idle-lock watchdog: {error}"
                            );

                            let _ = app_handle.emit(
                                "vault://auto-locked",
                                (),
                            );
                        }
                    }
                })?;

            if cfg!(debug_assertions) {
                app.handle().plugin(
                    tauri_plugin_log::Builder::default()
                        .level(log::LevelFilter::Info)
                        .build(),
                )?;
            }

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            vault_exists,
            derive_auth_secret,
            current_vault,
            lock_vault,
            touch_vault_activity,
            create_vault,
            unlock_vault,
            prepare_password_change,
            commit_password_change,
            vault_reset::reset_vault,
            get_identity_public_key,
            encrypt_new_item,
            decrypt_items_metadata,
            copy_item_password_to_clipboard,
            item_password_history,
            copy_item_history_password_to_clipboard,
            wrap_item_key_for_recipient,
            rekey_item,
            edit_item,
            load_items_cache,
            save_items_cache,
            prepare_invite,
            derive_invite_verifier,
            create_department_key,
            wrap_department_key,
            rotate_department_key,
            pending_invite_key,
            rewrap_invite_keys,
            finish_invite_rotation,
        ])
        .run(tauri::generate_context!())
        .expect("error while building tauri application");
}
