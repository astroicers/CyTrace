//! 密碼雜湊（argon2id / PHC 字串）。session/節流/middleware 隨 T803 增補。
//!
//! Provision 流程（ADR-011）：`cytrace hash-password` 離線產 PHC 字串 →
//! 放入 `CYTRACE_ADMIN_PASSWORD_HASH` → serve 啟動時驗格式。

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;

/// 密碼最短長度（ADR-011：只管長度，不搞複雜度規則）。
pub const MIN_PASSWORD_LEN: usize = 12;

/// 產 argon2id PHC 字串（如 `$argon2id$v=19$m=19456,t=2,p=1$...`）。
/// salt 取自 OS CSPRNG（getrandom；零網路）。
pub fn hash_password(password: &str) -> anyhow::Result<String> {
    let mut salt_bytes = [0u8; 16];
    getrandom::getrandom(&mut salt_bytes).map_err(|e| anyhow::anyhow!("getrandom: {e}"))?;
    let salt = SaltString::encode_b64(&salt_bytes).map_err(|e| anyhow::anyhow!("salt: {e}"))?;
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("argon2: {e}"))?;
    Ok(hash.to_string())
}

/// 驗證密碼與 PHC 字串是否相符。
pub fn verify_password(password: &str, phc: &str) -> anyhow::Result<bool> {
    let parsed = PasswordHash::new(phc).map_err(|e| anyhow::anyhow!("PHC 格式錯誤: {e}"))?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

/// PHC 字串格式是否合法（serve 啟動檢查用；不驗密碼本身）。
pub fn is_valid_phc(phc: &str) -> bool {
    PasswordHash::new(phc).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_then_verify_roundtrip() {
        let phc = hash_password("correct horse battery").unwrap();
        assert!(phc.starts_with("$argon2id$"));
        assert!(is_valid_phc(&phc));
        assert!(verify_password("correct horse battery", &phc).unwrap());
        assert!(!verify_password("wrong password!", &phc).unwrap());
    }

    #[test]
    fn invalid_phc_rejected() {
        assert!(!is_valid_phc("not-a-phc-string"));
        assert!(verify_password("x", "not-a-phc-string").is_err());
    }
}
