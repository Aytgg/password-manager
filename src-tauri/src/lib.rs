pub mod auth;
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

use crate::auth::authenticated_user_id;
use crate::crypto::{
    key_encryption::{protect_master_key, unlock_master_key},
    master_key::generate_master_key,
};
use crate::storage::{
    identity_store::{load_identity, load_or_create_identity},
    key_store::PlatformKeyStore,
};
use crate::vault::{
    key_file::{
        load_protected_master_key, replace_protected_master_key, save_protected_master_key,
    },
    owner_binding::{save_owner_binding, verify_owner_binding},
    items::{self, EncryptedItem, NewItem, Recipient, RekeyedItem, WrappedKeyDto},
    paths::VaultPaths,
    session::VaultSession,
};

const CLIPBOARD_CLEAR_AFTER_SECS: u64 = 30;
const MIN_MASTER_PASSWORD_CHARS: usize = 8;
const MAX_MASTER_PASSWORD_BYTES: usize = 1024;

fn validate_new_master_password(master_password: &str) -> Result<(), String> {
    if master_password.trim().is_empty() {
        return Err("Ana parola boş olamaz.".to_string());
    }

    if master_password.chars().count() < MIN_MASTER_PASSWORD_CHARS {
        return Err(format!(
            "Ana parola en az {MIN_MASTER_PASSWORD_CHARS} karakter olmalı."
        ));
    }

    if master_password.len() > MAX_MASTER_PASSWORD_BYTES {
        return Err("Ana parola çok uzun.".to_string());
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

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum VaultStatus {
    /// Bu hesap için kasa yok.
    Uninitialized,
    /// Bu hesabın kendi kasası var.
    Initialized,
}

#[tauri::command]
fn get_vault_status(
    app: tauri::AppHandle,
    session_token: String,
) -> Result<VaultStatus, String> {
    let user_id = authenticated_user_id(&session_token)?;
    let app_data_dir = app_data_dir(&app)?;

    if VaultPaths::for_user(&app_data_dir, &user_id)?.is_initialized() {
        return Ok(VaultStatus::Initialized);
    }

    Ok(VaultStatus::Uninitialized)
}

#[tauri::command]
fn is_vault_unlocked(
    session: tauri::State<'_, Arc<VaultSession>>,
    session_token: String,
) -> Result<bool, String> {
    let user_id = authenticated_user_id(&session_token)?;
    session.is_unlocked_for_user(&user_id)
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
    session_token: String,
) -> Result<(), String> {
    let user_id = authenticated_user_id(&session_token)?;
    session.record_activity_for_user(&user_id)
}

#[tauri::command]
async fn create_vault(
    app: tauri::AppHandle,
    session: tauri::State<'_, Arc<VaultSession>>,
    session_token: String,
    master_password: String,
) -> Result<(), String> {
    let user_id = authenticated_user_id(&session_token)?;
    let master_password = Zeroizing::new(master_password);

    validate_new_master_password(&master_password)?;

    let paths = VaultPaths::for_user(&app_data_dir(&app)?, &user_id)?;
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
            let master_key = generate_master_key();

            let protected_master_key = protect_master_key(
                master_password.as_bytes(),
                &master_key,
            )?;

            let key_store =
                PlatformKeyStore::open(&paths.stronghold, &master_key)?;

            let identity =
                load_or_create_identity(&key_store, &user_id)?.identity;

            save_protected_master_key(
                &paths.master_key,
                &protected_master_key,
            )?;

            save_owner_binding(
                &paths.owner_binding,
                &master_key,
                &user_id,
            )?;

            session.unlock(identity, key_store, user_id)?;

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

/// Ana parolayı değiştirir. Ana anahtar aynı kalır; yalnızca onu koruyan
/// paroladan türetilmiş anahtar değişir. Bu yüzden Stronghold, kimlik
/// anahtarı ve sunucudaki şifreli veriler etkilenmez.
#[tauri::command]
async fn change_master_password(
    app: tauri::AppHandle,
    session_token: String,
    current_password: String,
    new_password: String,
) -> Result<(), String> {
    let user_id = authenticated_user_id(&session_token)?;
    let current_password = Zeroizing::new(current_password);
    let new_password = Zeroizing::new(new_password);

    if current_password.is_empty() {
        return Err("Mevcut ana parolayı gir.".to_string());
    }

    validate_new_master_password(&new_password)?;

    if *current_password == *new_password {
        return Err("Yeni ana parola mevcut paroladan farklı olmalı.".to_string());
    }

    let paths = VaultPaths::for_user(&app_data_dir(&app)?, &user_id)?;

    tauri::async_runtime::spawn_blocking(move || {
        if !paths.is_complete() {
            return Err("Bu hesap için kasa bulunamadı.".to_string());
        }

        let protected_master_key = load_protected_master_key(&paths.master_key)?;

        let master_key = unlock_master_key(current_password.as_bytes(), &protected_master_key)
            .map_err(|_| "Mevcut ana parola yanlış.".to_string())?;

        verify_owner_binding(&paths.owner_binding, &master_key, &user_id)?;

        let new_protected = protect_master_key(new_password.as_bytes(), &master_key)?;

        replace_protected_master_key(&paths.master_key, &new_protected)
    })
    .await
    .map_err(|error| error.to_string())?
}

#[tauri::command]
async fn unlock_vault(
    app: tauri::AppHandle,
    session: tauri::State<'_, Arc<VaultSession>>,
    session_token: String,
    master_password: String,
) -> Result<(), String> {
    let user_id = authenticated_user_id(&session_token)?;
    let master_password = Zeroizing::new(master_password);

    if master_password.is_empty() {
        return Err("Ana parola boş olamaz.".to_string());
    }

    if session.is_unlocked_for_user(&user_id)? {
        return Ok(());
    }

    let paths = VaultPaths::for_user(&app_data_dir(&app)?, &user_id)?;
    let session = session.inner().clone();

    tauri::async_runtime::spawn_blocking(move || {
        if !paths.is_complete() {
            return Err(
                "Kasa dosyalarından biri eksik. Kasa açılamadı."
                    .to_string(),
            );
        }

        let protected_master_key =
            load_protected_master_key(&paths.master_key)?;

        let master_key = unlock_master_key(
            master_password.as_bytes(),
            &protected_master_key,
        )?;

        verify_owner_binding(
            &paths.owner_binding,
            &master_key,
            &user_id,
        )?;

        let key_store =
            PlatformKeyStore::open(&paths.stronghold, &master_key)?;

        let identity = load_identity(&key_store, &user_id)?;

        session.unlock(identity, key_store, user_id)?;

        Ok::<(), String>(())
    })
    .await
    .map_err(|error| error.to_string())?
}

/// Bu hesabın X25519 açık anahtarı (base64). Convex'teki kullanıcı kaydına
/// yazılır; diğer kullanıcılar paylaşım yaparken bu anahtara paketler.
#[tauri::command]
fn get_identity_public_key(
    session: tauri::State<'_, Arc<VaultSession>>,
    session_token: String,
) -> Result<String, String> {
    let user_id = authenticated_user_id(&session_token)?;

    session.with_identity_for_user(&user_id, |identity| {
        Ok(items::encode_public_key(&identity.public_key()))
    })
}

#[tauri::command]
fn encrypt_new_item(
    session: tauri::State<'_, Arc<VaultSession>>,
    session_token: String,
    title: String,
    username: Option<String>,
    password: String,
) -> Result<NewItem, String> {
    let user_id = authenticated_user_id(&session_token)?;
    let password = Zeroizing::new(password);

    session.with_identity_for_user(&user_id, |identity| {
        items::encrypt_new_item(
            identity,
            &user_id,
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
    session_token: String,
    items: Vec<EncryptedItem>,
) -> Result<Vec<DecryptedItemMetadata>, String> {
    let user_id = authenticated_user_id(&session_token)?;

    session.with_identity_for_user(&user_id, |identity| {
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
    session_token: String,
    item: EncryptedItem,
) -> Result<(), String> {
    let user_id = authenticated_user_id(&session_token)?;

    let plaintext_bytes = session.with_identity_for_user(&user_id, |identity| {
        items::decrypt_secret(identity, &item)
    })?;

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
    session_token: String,
    item: EncryptedItem,
    recipient_public_key: String,
) -> Result<WrappedKeyDto, String> {
    let user_id = authenticated_user_id(&session_token)?;

    session.with_identity_for_user(&user_id, |identity| {
        items::wrap_for_recipient(identity, &item, &recipient_public_key)
    })
}

#[tauri::command]
fn rekey_item(
    session: tauri::State<'_, Arc<VaultSession>>,
    session_token: String,
    item: EncryptedItem,
    recipients: Vec<Recipient>,
) -> Result<RekeyedItem, String> {
    let user_id = authenticated_user_id(&session_token)?;

    session.with_identity_for_user(&user_id, |identity| {
        items::rekey(identity, &user_id, &item, &recipients)
    })
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
            get_vault_status,
            is_vault_unlocked,
            lock_vault,
            touch_vault_activity,
            create_vault,
            unlock_vault,
            change_master_password,
            vault_reset::reset_vault,
            get_identity_public_key,
            encrypt_new_item,
            decrypt_items_metadata,
            copy_item_password_to_clipboard,
            wrap_item_key_for_recipient,
            rekey_item,
        ])
        .run(tauri::generate_context!())
        .expect("error while building tauri application");
}
