use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use serde::Deserialize;
use std::sync::OnceLock;

#[derive(Debug, Deserialize)]
struct ClerkClaims {
    sub: String,
    iss: String,
    exp: usize,
    #[serde(default)]
    nbf: Option<usize>,
    #[serde(default)]
    azp: Option<String>,
    #[serde(default)]
    sts: Option<String>,
}

struct ClerkConfig {
    decoding_key: DecodingKey,
    issuer: String,
    allowed_parties: Vec<String>,
}

/// Değerler build.rs tarafından derleme anında gömülür. Çalışma zamanındaki
/// ortam değişkenleri bilinçli olarak dikkate alınmaz; aksi halde yerel bir
/// süreç kendi doğrulama anahtarını tanımlayıp sahte token üretebilirdi.
fn clerk_config() -> Result<&'static ClerkConfig, String> {
    static CONFIG: OnceLock<Result<ClerkConfig, String>> = OnceLock::new();

    CONFIG
        .get_or_init(load_clerk_config)
        .as_ref()
        .map_err(Clone::clone)
}

fn load_clerk_config() -> Result<ClerkConfig, String> {
    let public_key = option_env!("CLERK_JWKS_PUBLIC_KEY")
        .ok_or_else(|| "CLERK_JWKS_PUBLIC_KEY yapılandırılmamış.".to_string())?;

    let issuer = option_env!("CLERK_ISSUER")
        .ok_or_else(|| "CLERK_ISSUER yapılandırılmamış.".to_string())?
        .trim()
        .to_string();

    let allowed_parties = option_env!("CLERK_AUTHORIZED_PARTIES")
        .ok_or_else(|| "CLERK_AUTHORIZED_PARTIES yapılandırılmamış.".to_string())?
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();

    if allowed_parties.is_empty() {
        return Err("En az bir izinli Clerk istemci adresi tanımlanmalıdır.".to_string());
    }

    let public_key = public_key.replace("\\n", "\n");

    let decoding_key = DecodingKey::from_rsa_pem(public_key.as_bytes())
        .map_err(|_| "Clerk JWT doğrulama anahtarı geçersiz.".to_string())?;

    Ok(ClerkConfig {
        decoding_key,
        issuer,
        allowed_parties,
    })
}

pub fn authenticated_user_id(session_token: &str) -> Result<String, String> {
    if session_token.trim().is_empty() {
        return Err("Oturum token'ı eksik.".to_string());
    }

    let config = clerk_config()?;

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[config.issuer.as_str()]);
    validation.set_required_spec_claims(&["exp", "iss", "sub"]);
    validation.validate_exp = true;
    validation.validate_nbf = true;
    validation.validate_aud = false;
    validation.leeway = 5;

    let token_data = decode::<ClerkClaims>(session_token.trim(), &config.decoding_key, &validation)
        .map_err(|_| "Clerk oturumu geçersiz veya süresi dolmuş.".to_string())?;

    let claims = token_data.claims;

    // Issuer değerini doğrulama kütüphanesi de denetler.
    if claims.iss != config.issuer {
        return Err("Clerk oturumunun issuer değeri geçersiz.".to_string());
    }

    // WebView kaynağı izin verilen istemcilerden biri olmalı.
    match claims.azp.as_deref() {
        Some(azp) if config.allowed_parties.iter().any(|allowed| allowed == azp) => {}
        _ => {
            return Err("Clerk oturumu izin verilen istemci kaynağından gelmiyor.".to_string());
        }
    }

    if claims.sts.as_deref() == Some("pending") {
        return Err("Clerk oturumu henüz etkinleştirilmemiş.".to_string());
    }

    // Bu alanlar doğrulama sırasında kullanılır.
    let _expiration = claims.exp;
    let _not_before = claims.nbf;

    if claims.sub.trim().is_empty() {
        return Err("Clerk kullanıcı kimliği boş.".to_string());
    }

    Ok(claims.sub)
}
