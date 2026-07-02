//! 服務設定。來源優先序：CLI 旗標 > 環境變數 > 預設（SDS §6 慣例）。
//!
//! `resolve` 是純函式（env 以 `HashMap` 傳入）——可單元測試且無測試間 env 競態。

use crate::auth;
use cytrace_core::error::{CytraceError, Result};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

/// 預設監聽位址（容器由 `CYTRACE_BIND=0.0.0.0:8443` 覆寫；預設只綁 loopback 安全優先）。
pub const DEFAULT_BIND: &str = "127.0.0.1:8443";
/// 預設資料目錄（ADR-011；容器掛 volume，裸機以 `--data-dir` 覆寫）。
pub const DEFAULT_DATA_DIR: &str = "/data";
/// 預設 session TTL（小時，絕對過期不 sliding）。
pub const DEFAULT_SESSION_TTL_HOURS: u64 = 12;

/// CLI 旗標（`cytrace serve` 傳入；旗標優先於環境變數）。
#[derive(Debug, Clone, Default)]
pub struct CliFlags {
    pub bind: Option<String>,
    pub data_dir: Option<PathBuf>,
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
}

/// TLS 憑證組（自帶 PEM；兩者必須成對）。
#[derive(Debug, Clone)]
pub struct TlsPaths {
    pub cert: PathBuf,
    pub key: PathBuf,
}

/// 服務設定（jobs/上限等欄位隨 T804–T805 增補）。
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub bind: SocketAddr,
    pub data_dir: PathBuf,
    /// grype DB 快照位置（`GRYPE_DB_CACHE_DIR`）。缺失時 degraded 啟動（ADR-012 C3）。
    pub db_cache_dir: Option<PathBuf>,
    /// 管理密碼 argon2id PHC（`CYTRACE_ADMIN_PASSWORD_HASH`；缺失/不合法拒絕啟動）。
    pub admin_password_hash: String,
    /// 管理帳號顯示名（`CYTRACE_ADMIN_USER`，預設 `admin`）。
    pub admin_user: String,
    /// session 絕對過期時間（`CYTRACE_SESSION_TTL_HOURS`）。
    pub session_ttl: Duration,
    /// TLS 憑證（未設 = HTTP 明文，啟動時警告）。
    pub tls: Option<TlsPaths>,
}

impl ServerConfig {
    /// 由 CLI 旗標與環境變數解析設定。
    pub fn resolve(flags: CliFlags, env: HashMap<String, String>) -> Result<Self> {
        let bind_raw = flags
            .bind
            .or_else(|| env.get("CYTRACE_BIND").cloned())
            .unwrap_or_else(|| DEFAULT_BIND.to_string());
        let bind: SocketAddr = bind_raw
            .parse()
            .map_err(|_| CytraceError::Config(format!("CYTRACE_BIND 不是合法位址：{bind_raw}")))?;

        let data_dir = flags
            .data_dir
            .or_else(|| env.get("CYTRACE_DATA_DIR").map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from(DEFAULT_DATA_DIR));

        let db_cache_dir = env.get("GRYPE_DB_CACHE_DIR").map(PathBuf::from);

        let admin_password_hash =
            env.get("CYTRACE_ADMIN_PASSWORD_HASH")
                .cloned()
                .ok_or_else(|| {
                    CytraceError::Config(
                        "缺少 CYTRACE_ADMIN_PASSWORD_HASH（以 `cytrace hash-password` 產生）"
                            .into(),
                    )
                })?;
        if !auth::is_valid_phc(&admin_password_hash) {
            return Err(CytraceError::Config(
                "CYTRACE_ADMIN_PASSWORD_HASH 不是合法 PHC 字串（以 `cytrace hash-password` 產生）"
                    .into(),
            ));
        }

        let admin_user = env
            .get("CYTRACE_ADMIN_USER")
            .cloned()
            .unwrap_or_else(|| "admin".into());

        let ttl_hours = match env.get("CYTRACE_SESSION_TTL_HOURS") {
            Some(raw) => raw.parse::<u64>().map_err(|_| {
                CytraceError::Config(format!("CYTRACE_SESSION_TTL_HOURS 不是整數：{raw}"))
            })?,
            None => DEFAULT_SESSION_TTL_HOURS,
        };
        let session_ttl = Duration::from_secs(ttl_hours * 3600);

        let tls_cert = flags
            .tls_cert
            .or_else(|| env.get("CYTRACE_TLS_CERT").map(PathBuf::from));
        let tls_key = flags
            .tls_key
            .or_else(|| env.get("CYTRACE_TLS_KEY").map(PathBuf::from));
        let tls = match (tls_cert, tls_key) {
            (Some(cert), Some(key)) => Some(TlsPaths { cert, key }),
            (None, None) => None,
            _ => {
                return Err(CytraceError::Config(
                    "TLS 憑證與金鑰必須成對設定（CYTRACE_TLS_CERT + CYTRACE_TLS_KEY）".into(),
                ))
            }
        };

        Ok(ServerConfig {
            bind,
            data_dir,
            db_cache_dir,
            admin_password_hash,
            admin_user,
            session_ttl,
            tls,
        })
    }

    /// grype DB 快照是否就位（目錄存在且非空）。缺失＝degraded：服務可起、掃描回 503。
    pub fn db_present(&self) -> bool {
        self.db_cache_dir
            .as_deref()
            .and_then(|d| std::fs::read_dir(d).ok())
            .map(|mut it| it.next().is_some())
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::LazyLock;

    /// 測試用 PHC（argon2 hash 一次 ~100ms，全部測試共用）。
    pub(crate) static TEST_PHC: LazyLock<String> =
        LazyLock::new(|| auth::hash_password("test-password-123").unwrap());

    fn env(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        let mut m: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        m.entry("CYTRACE_ADMIN_PASSWORD_HASH".into())
            .or_insert_with(|| TEST_PHC.clone());
        m
    }

    #[test]
    fn flag_overrides_env_overrides_default() {
        let c = ServerConfig::resolve(
            CliFlags {
                bind: Some("127.0.0.1:9999".into()),
                ..Default::default()
            },
            env(&[("CYTRACE_BIND", "0.0.0.0:1234")]),
        )
        .unwrap();
        assert_eq!(c.bind.port(), 9999);

        let c = ServerConfig::resolve(
            CliFlags::default(),
            env(&[("CYTRACE_BIND", "0.0.0.0:1234")]),
        )
        .unwrap();
        assert_eq!(c.bind.port(), 1234);

        let c = ServerConfig::resolve(CliFlags::default(), env(&[])).unwrap();
        assert_eq!(c.bind.to_string(), DEFAULT_BIND);
        assert_eq!(c.data_dir, PathBuf::from(DEFAULT_DATA_DIR));
        assert_eq!(c.admin_user, "admin");
        assert_eq!(c.session_ttl, Duration::from_secs(12 * 3600));
        assert!(c.tls.is_none());
    }

    #[test]
    fn invalid_bind_is_config_error() {
        let err = ServerConfig::resolve(
            CliFlags {
                bind: Some("not-an-addr".into()),
                ..Default::default()
            },
            env(&[]),
        )
        .unwrap_err();
        assert!(matches!(err, CytraceError::Config(_)));
    }

    #[test]
    fn admin_hash_required_and_validated() {
        // 缺失 → 拒絕啟動
        let err = ServerConfig::resolve(CliFlags::default(), HashMap::new()).unwrap_err();
        assert!(matches!(err, CytraceError::Config(_)));
        // 非 PHC → 拒絕啟動
        let err = ServerConfig::resolve(
            CliFlags::default(),
            [(
                "CYTRACE_ADMIN_PASSWORD_HASH".to_string(),
                "plaintext-password".to_string(),
            )]
            .into(),
        )
        .unwrap_err();
        assert!(matches!(err, CytraceError::Config(_)));
    }

    #[test]
    fn tls_must_be_paired() {
        let err = ServerConfig::resolve(
            CliFlags {
                tls_cert: Some("/certs/tls.crt".into()),
                ..Default::default()
            },
            env(&[]),
        )
        .unwrap_err();
        assert!(matches!(err, CytraceError::Config(_)));

        let c = ServerConfig::resolve(
            CliFlags::default(),
            env(&[
                ("CYTRACE_TLS_CERT", "/certs/tls.crt"),
                ("CYTRACE_TLS_KEY", "/certs/tls.key"),
            ]),
        )
        .unwrap();
        assert!(c.tls.is_some());
    }

    #[test]
    fn db_absent_when_env_unset_or_dir_missing() {
        let c = ServerConfig::resolve(CliFlags::default(), env(&[])).unwrap();
        assert!(!c.db_present());
        let c = ServerConfig::resolve(
            CliFlags::default(),
            env(&[("GRYPE_DB_CACHE_DIR", "/no/such/dir")]),
        )
        .unwrap();
        assert!(!c.db_present());
    }
}
