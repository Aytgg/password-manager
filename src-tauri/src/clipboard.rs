use tauri::AppHandle;

#[cfg(target_os = "macos")]
pub fn write_sensitive_text(
    _app: &AppHandle,
    text: &str,
) -> Result<(), String> {
    use objc2_app_kit::{
        NSPasteboard,
        NSPasteboardTypeString,
    };
    use objc2_foundation::{NSArray, NSData, NSString};

    let pasteboard = NSPasteboard::generalPasteboard();

    let string_type = unsafe { NSPasteboardTypeString };

    let concealed_type =
        NSString::from_str("org.nspasteboard.ConcealedType");

    let transient_type =
        NSString::from_str("org.nspasteboard.TransientType");

    let types = NSArray::from_slice(&[
        string_type,
        &concealed_type,
        &transient_type,
    ]);

    unsafe {
        pasteboard.declareTypes_owner(&types, None);
    }

    let marker = NSData::new();

    if !pasteboard.setData_forType(
        Some(&marker),
        &concealed_type,
    ) {
        return Err(
            "Gizlilik işareti panoya yazılamadı.".to_string(),
        );
    }

    if !pasteboard.setData_forType(
        Some(&marker),
        &transient_type,
    ) {
        return Err(
            "Geçici içerik işareti panoya yazılamadı.".to_string(),
        );
    }

    let value = NSString::from_str(text);

    if !pasteboard.setString_forType(
        &value,
        string_type,
    ) {
        return Err("Parola panoya yazılamadı.".to_string());
    }

    Ok(())
}

#[cfg(not(target_os = "macos"))]
pub fn write_sensitive_text(
    app: &AppHandle,
    text: &str,
) -> Result<(), String> {
    use tauri_plugin_clipboard_manager::ClipboardExt;

    app.clipboard()
        .write_text(text)
        .map_err(|error| {
            format!("Parola panoya yazılamadı: {error}")
        })
}
