use std::path::Path;

/// Clerk doğrulaması için gereken ve derleme anında binary'ye gömülen ayarlar.
/// Kurulu uygulama `.env.local` dosyasına erişemeyeceği için bu değerler
/// çalışma zamanında değil, derleme sırasında okunur.
const EMBEDDED_ENV_KEYS: &[&str] = &[
    "CLERK_JWKS_PUBLIC_KEY",
    "CLERK_ISSUER",
    "CLERK_AUTHORIZED_PARTIES",
];

fn main() {
    embed_clerk_configuration();
    tauri_build::build()
}

fn embed_clerk_configuration() {
    let env_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("proje kök dizini bulunamadı")
        .join(".env.local");

    println!("cargo:rerun-if-changed={}", env_path.display());

    let file_values: Vec<(String, String)> = if env_path.is_file() {
        dotenvy::from_path_iter(&env_path)
            .unwrap_or_else(|error| panic!(".env.local okunamadı: {error}"))
            .collect::<Result<_, _>>()
            .unwrap_or_else(|error| panic!(".env.local ayrıştırılamadı: {error}"))
    } else {
        Vec::new()
    };

    let is_release = std::env::var("PROFILE").as_deref() == Ok("release");

    for key in EMBEDDED_ENV_KEYS {
        println!("cargo:rerun-if-env-changed={key}");

        // İşletim sisteminden gelen ortam değişkenleri önceliklidir (CI için).
        let value = std::env::var(key).ok().or_else(|| {
            file_values
                .iter()
                .find(|(name, _)| name == key)
                .map(|(_, value)| value.clone())
        });

        match value {
            // rustc-env değerleri satır sonu içeremez; PEM satırları
            // `\n` kaçış dizisi olarak gömülür ve çalışma zamanında açılır.
            Some(value) => println!(
                "cargo:rustc-env={key}={}",
                value.replace("\r\n", "\n").replace('\n', "\\n")
            ),
            None if is_release => {
                panic!("{key} tanımlı değil; yayın sürümü Clerk doğrulaması olmadan derlenemez.")
            }
            None => println!("cargo:warning={key} tanımlı değil; Clerk doğrulaması çalışmayacak."),
        }
    }
}
