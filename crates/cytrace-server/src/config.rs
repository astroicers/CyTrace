//! 服務設定。來源優先序：CLI 旗標 > 環境變數 > 預設（SDS §6 慣例）。
//!
//! `resolve` 是純函式（env 以 `HashMap` 傳入）——可單元測試且無測試間 env 競態。

use cytrace_core::error::{CytraceError, Result};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;

/// 預設監聽位址（容器由 `CYTRACE_BIND=0.0.0.0:8443` 覆寫；預設只綁 loopback 安全優先）。
pub const DEFAULT_BIND: &str = "127.0.0.1:8443";
/// 預設資料目錄（ADR-011；容器掛 volume，裸機以 `--data-dir` 覆寫）。
pub const DEFAULT_DATA_DIR: &str = "/data";

/// 服務設定（jobs/TLS/上限等欄位隨 T803–T805 增補）。
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub bind: SocketAddr,
    pub data_dir: PathBuf,
    /// grype DB 快照位置（`GRYPE_DB_CACHE_DIR`）。缺失時 degraded 啟動（ADR-012 C3）。
    pub db_cache_dir: Option<PathBuf>,
}

impl ServerConfig {
    /// 由 CLI 旗標與環境變數解析設定。
    pub fn resolve(
        bind_flag: Option<String>,
        data_dir_flag: Option<PathBuf>,
        env: HashMap<String, String>,
    ) -> Result<Self> {
        let bind_raw = bind_flag
            .or_else(|| env.get("CYTRACE_BIND").cloned())
            .unwrap_or_else(|| DEFAULT_BIND.to_string());
        let bind: SocketAddr = bind_raw
            .parse()
            .map_err(|_| CytraceError::Config(format!("CYTRACE_BIND 不是合法位址：{bind_raw}")))?;
        let data_dir = data_dir_flag
            .or_else(|| env.get("CYTRACE_DATA_DIR").map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from(DEFAULT_DATA_DIR));
        let db_cache_dir = env.get("GRYPE_DB_CACHE_DIR").map(PathBuf::from);
        Ok(ServerConfig {
            bind,
            data_dir,
            db_cache_dir,
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

    fn env(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn flag_overrides_env_overrides_default() {
        let c = ServerConfig::resolve(
            Some("127.0.0.1:9999".into()),
            None,
            env(&[("CYTRACE_BIND", "0.0.0.0:1234")]),
        )
        .unwrap();
        assert_eq!(c.bind.port(), 9999);

        let c =
            ServerConfig::resolve(None, None, env(&[("CYTRACE_BIND", "0.0.0.0:1234")])).unwrap();
        assert_eq!(c.bind.port(), 1234);

        let c = ServerConfig::resolve(None, None, HashMap::new()).unwrap();
        assert_eq!(c.bind.to_string(), DEFAULT_BIND);
        assert_eq!(c.data_dir, PathBuf::from(DEFAULT_DATA_DIR));
    }

    #[test]
    fn invalid_bind_is_config_error() {
        let err =
            ServerConfig::resolve(Some("not-an-addr".into()), None, HashMap::new()).unwrap_err();
        assert!(matches!(err, CytraceError::Config(_)));
    }

    #[test]
    fn db_absent_when_env_unset_or_dir_missing() {
        let c = ServerConfig::resolve(None, None, HashMap::new()).unwrap();
        assert!(!c.db_present());
        let c = ServerConfig::resolve(None, None, env(&[("GRYPE_DB_CACHE_DIR", "/no/such/dir")]))
            .unwrap();
        assert!(!c.db_present());
    }
}
