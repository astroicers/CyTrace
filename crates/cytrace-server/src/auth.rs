//! 密碼雜湊（argon2id / PHC 字串）、登入節流、auth / CSRF middleware（ADR-011 §3）。
//!
//! Provision 流程：`cytrace hash-password` 離線產 PHC 字串 →
//! 放入 `CYTRACE_ADMIN_PASSWORD_HASH` → serve 啟動時驗格式（缺失/不合法拒絕啟動）。

use crate::error::{ApiError, ErrorKind, Lang};
use crate::session::token_from_cookie_header;
use crate::state::AppState;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use axum::extract::{Request, State};
use axum::http::{header, Method};
use axum::middleware::Next;
use axum::response::Response;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

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

/// 登入節流（in-memory、固定 15 分鐘窗；重啟歸零）。per-IP 5 次 + 全域 20 次。
pub struct LoginThrottle {
    window: Duration,
    per_ip_limit: usize,
    global_limit: usize,
    inner: Mutex<ThrottleState>,
}

#[derive(Default)]
struct ThrottleState {
    per_ip: HashMap<IpAddr, Vec<Instant>>,
    global: Vec<Instant>,
}

impl Default for LoginThrottle {
    fn default() -> Self {
        LoginThrottle::new(Duration::from_secs(900), 5, 20)
    }
}

impl LoginThrottle {
    pub fn new(window: Duration, per_ip_limit: usize, global_limit: usize) -> Self {
        LoginThrottle {
            window,
            per_ip_limit,
            global_limit,
            inner: Mutex::new(ThrottleState::default()),
        }
    }

    /// 是否放行本次登入嘗試；擋下時回 `Err(建議 Retry-After 秒數)`。
    pub fn check(&self, ip: IpAddr) -> Result<(), u64> {
        let now = Instant::now();
        let retry = self.window.as_secs();
        let Ok(mut st) = self.inner.lock() else {
            return Ok(()); // lock poisoned：fail-open（單管理員 LAN，可用性優先）
        };
        st.global.retain(|t| now.duration_since(*t) < self.window);
        st.per_ip.retain(|_, v| {
            v.retain(|t| now.duration_since(*t) < self.window);
            !v.is_empty()
        });
        if st.global.len() >= self.global_limit {
            return Err(retry);
        }
        if st.per_ip.get(&ip).map(Vec::len).unwrap_or(0) >= self.per_ip_limit {
            return Err(retry);
        }
        Ok(())
    }

    /// 記錄一次登入失敗。
    pub fn record_failure(&self, ip: IpAddr) {
        let now = Instant::now();
        if let Ok(mut st) = self.inner.lock() {
            st.global.push(now);
            st.per_ip.entry(ip).or_default().push(now);
        }
    }
}

/// 由 request 取出協商語言（middleware 用；extractor 版見 [`Lang`]）。
fn lang_of(req: &Request) -> Lang {
    let al = req
        .headers()
        .get(header::ACCEPT_LANGUAGE)
        .and_then(|v| v.to_str().ok());
    Lang::negotiate(req.uri().query(), al)
}

/// 受保護路由的 auth middleware：驗 session cookie，無效一律 401。
pub async fn require_session(
    State(app): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let lang = lang_of(&req);
    let token = req
        .headers()
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(token_from_cookie_header);
    match token {
        Some(t) if app.sessions.validate(t).is_some() => Ok(next.run(req).await),
        _ => Err(ApiError::new(lang, ErrorKind::Auth)),
    }
}

/// CSRF 防護（ADR-011 §3 第 2 層）：變更型方法必帶 `X-CyTrace-Request: 1`。
/// 跨站表單帶不了自訂標頭；帶了會觸發 preflight，而本服務不啟用 CORS → 瀏覽器直接擋。
pub const CSRF_HEADER: &str = "x-cytrace-request";

pub async fn csrf_guard(req: Request, next: Next) -> Result<Response, ApiError> {
    let mutating = matches!(
        *req.method(),
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    );
    if mutating && req.headers().get(CSRF_HEADER).is_none() {
        return Err(ApiError::new(lang_of(&req), ErrorKind::Csrf));
    }
    Ok(next.run(req).await)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn throttle_blocks_after_per_ip_limit() {
        let t = LoginThrottle::new(Duration::from_secs(900), 3, 100);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        for _ in 0..3 {
            assert!(t.check(ip).is_ok());
            t.record_failure(ip);
        }
        assert!(t.check(ip).is_err());
        // 其他 IP 不受影響（未達全域上限）
        assert!(t.check("10.0.0.2".parse().unwrap()).is_ok());
    }

    #[test]
    fn throttle_global_limit_covers_distributed_sources() {
        let t = LoginThrottle::new(Duration::from_secs(900), 100, 4);
        for i in 0..4 {
            let ip: IpAddr = format!("10.0.1.{i}").parse().unwrap();
            assert!(t.check(ip).is_ok());
            t.record_failure(ip);
        }
        assert!(t.check("10.0.9.9".parse().unwrap()).is_err());
    }

    #[test]
    fn throttle_window_expires() {
        let t = LoginThrottle::new(Duration::from_millis(10), 1, 100);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        t.record_failure(ip);
        assert!(t.check(ip).is_err());
        std::thread::sleep(Duration::from_millis(20));
        assert!(t.check(ip).is_ok());
    }

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
