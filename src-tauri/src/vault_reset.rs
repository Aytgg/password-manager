use std::sync::Arc;

use tauri::Manager;

use crate::auth::authenticated_user_id;
use crate::vault::{paths::VaultPaths, session::VaultSession};

fn remove_file_if_exists(path: &std::path::Path) -> Result<(), String> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "Kasa dosyası silinemedi ({}): {error}",
            path.display()
        )),
    }
}

/// Development-only command that discards the authenticated user's local
/// vault on this device. Other accounts' vaults are left untouched.
/// Release builds always refuse to execute this operation.
#[tauri::command]
pub fn reset_vault(
    app: tauri::AppHandle,
    session: tauri::State<'_, Arc<VaultSession>>,
    session_token: String,
) -> Result<(), String> {
    if !cfg!(debug_assertions) {
        return Err(
            "Yerel kasa sıfırlama özelliği yalnızca geliştirme sürümünde kullanılabilir."
                .to_string(),
        );
    }

    let user_id = authenticated_user_id(&session_token)?;

    // Lock and release the database/Stronghold runtime before deleting files.
    session.lock()?;

    let app_data_dir = app
        .path()
        .app_data_dir()
        .map_err(|error| error.to_string())?;

    let paths = VaultPaths::for_user(&app_data_dir, &user_id)?;

    for path in paths.all_files() {
        remove_file_if_exists(path)?;
    }

    // Klasör artık boşsa kaldır; boş değilse (beklenmeyen dosya) bırak.
    let _ = std::fs::remove_dir(&paths.dir);

    Ok(())
}
