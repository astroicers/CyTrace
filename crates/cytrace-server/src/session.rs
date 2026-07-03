//! In-memory session store（ADR-011 §3）。
//!
//! - token：32 bytes CSPRNG → hex；**伺服端只存 token 的 SHA-256**（記憶體 dump 拿不到可重放 token）
//! - TTL 絕對過期（預設 12h，不 sliding）；重啟即全部登出（無 DB 哲學，單一管理員可接受）

use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, SystemTime};

/// session cookie 名稱。
pub const COOKIE_NAME: &str = "cytrace_session";

#[derive(Debug, Clone, Copy)]
pub struct Session {
    pub created_at: SystemTime,
    pub expires_at: SystemTime,
}

pub struct SessionStore {
    ttl: Duration,
    inner: RwLock<HashMap<[u8; 32], Session>>,
}

fn hash_token(token_hex: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(token_hex.as_bytes());
    h.finalize().into()
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

impl SessionStore {
    pub fn new(ttl: Duration) -> Self {
        SessionStore {
            ttl,
            inner: RwLock::new(HashMap::new()),
        }
    }

    /// 建立 session，回傳要放進 cookie 的 hex token。
    pub fn create(&self) -> anyhow::Result<String> {
        let mut raw = [0u8; 32];
        getrandom::getrandom(&mut raw).map_err(|e| anyhow::anyhow!("getrandom: {e}"))?;
        let token = to_hex(&raw);
        let now = SystemTime::now();
        let session = Session {
            created_at: now,
            expires_at: now + self.ttl,
        };
        if let Ok(mut map) = self.inner.write() {
            // 順手清過期（無背景 timer，保持簡單）
            map.retain(|_, s| s.expires_at > now);
            map.insert(hash_token(&token), session);
        }
        Ok(token)
    }

    /// 驗 token：存在且未過期 → 回 session；過期則移除。
    pub fn validate(&self, token_hex: &str) -> Option<Session> {
        let key = hash_token(token_hex);
        let now = SystemTime::now();
        let mut map = self.inner.write().ok()?;
        match map.get(&key) {
            Some(s) if s.expires_at > now => Some(*s),
            Some(_) => {
                map.remove(&key);
                None
            }
            None => None,
        }
    }

    /// 登出：移除 session（不存在也視為成功，冪等）。
    pub fn revoke(&self, token_hex: &str) {
        if let Ok(mut map) = self.inner.write() {
            map.remove(&hash_token(token_hex));
        }
    }
}

/// 組登入成功的 Set-Cookie 值（HttpOnly + SameSite=Strict；TLS 時 + Secure）。
pub fn login_cookie(token: &str, secure: bool) -> String {
    let base = format!("{COOKIE_NAME}={token}; HttpOnly; SameSite=Strict; Path=/");
    if secure {
        format!("{base}; Secure")
    } else {
        base
    }
}

/// 組登出的 Set-Cookie 值（立即失效）。
pub fn logout_cookie(secure: bool) -> String {
    let base = format!("{COOKIE_NAME}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0");
    if secure {
        format!("{base}; Secure")
    } else {
        base
    }
}

/// 從 Cookie 標頭值取出 session token。
pub fn token_from_cookie_header(header: &str) -> Option<&str> {
    header.split(';').find_map(|pair| {
        let (k, v) = pair.trim().split_once('=')?;
        (k == COOKIE_NAME).then_some(v)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_validate_revoke_roundtrip() {
        let store = SessionStore::new(Duration::from_secs(3600));
        let token = store.create().unwrap();
        assert_eq!(token.len(), 64);
        assert!(store.validate(&token).is_some());
        store.revoke(&token);
        assert!(store.validate(&token).is_none());
    }

    #[test]
    fn zero_ttl_expires_immediately() {
        let store = SessionStore::new(Duration::from_secs(0));
        let token = store.create().unwrap();
        assert!(store.validate(&token).is_none());
    }

    #[test]
    fn unknown_or_tampered_token_rejected() {
        let store = SessionStore::new(Duration::from_secs(3600));
        let token = store.create().unwrap();
        let mut tampered = token.clone();
        tampered.replace_range(0..2, if &token[0..2] == "00" { "01" } else { "00" });
        assert!(store.validate(&tampered).is_none());
        assert!(store.validate("deadbeef").is_none());
    }

    #[test]
    fn cookie_helpers() {
        let c = login_cookie("abc", false);
        assert!(c.contains("cytrace_session=abc"));
        assert!(c.contains("HttpOnly") && c.contains("SameSite=Strict"));
        assert!(!c.contains("Secure"));
        assert!(login_cookie("abc", true).contains("; Secure"));
        assert!(logout_cookie(false).contains("Max-Age=0"));
        assert_eq!(
            token_from_cookie_header("foo=1; cytrace_session=tok123; bar=2"),
            Some("tok123")
        );
        assert_eq!(token_from_cookie_header("foo=1"), None);
    }
}
