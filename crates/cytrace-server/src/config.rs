//! 服務設定。來源優先序：CLI 旗標 > 環境變數 > 預設（SDS §6 慣例）。
//!
//! `resolve` 是純函式（env 以 `HashMap` 傳入）——可單元測試且無測試間 env 競態。
//! 錯誤以 [`Localized`] 回傳（`server.startup.*`），由呼叫端以操作者語言渲染（T912）。

use crate::auth;
use crate::error::Lang;
use cytrace_i18n::Localized;
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
    /// 掛載掃描白名單（`CYTRACE_SCAN_ROOTS=name=/abs/path,...`）。
    pub scan_roots: Vec<(String, PathBuf)>,
    /// 同時掃描上限（`CYTRACE_MAX_CONCURRENT_SCANS`，預設 2）。
    pub max_concurrent_scans: usize,
    /// 佇列上限——非終態 job 總數（`CYTRACE_MAX_QUEUED`，預設 32）。
    pub max_queued: usize,
    /// 掃描完成後保留上傳原檔（`CYTRACE_KEEP_INPUT`，預設 false）。
    pub keep_input: bool,
    /// 上傳大小上限 bytes（`CYTRACE_MAX_UPLOAD_MB`，預設 512MB）。
    pub max_upload_bytes: u64,
    /// 總解壓量上限 bytes（`CYTRACE_MAX_EXTRACT_MB`，預設 min(10×上傳, 4GB)）。
    pub max_extract_bytes: u64,
    /// 操作者語言：終端機訊息（啟動、job 隔離／落盤失敗）用。`resolve` 給 zh-TW，
    /// 由 `serve` 依 CLI 的 `--lang`／`CYTRACE_LANG` 覆寫。與 API 回應的語言（每個請求各自協商）無關。
    pub lang: Lang,
}

impl ServerConfig {
    /// 由 CLI 旗標與環境變數解析設定。
    pub fn resolve(flags: CliFlags, env: HashMap<String, String>) -> Result<Self, Localized> {
        // 錯誤訊息指名值的實際來源（旗標或環境變數），操作者才知道要改哪裡
        let (bind_source, bind_raw) = match (flags.bind, env.get("CYTRACE_BIND")) {
            (Some(v), _) => ("--bind", v),
            (None, Some(v)) => ("CYTRACE_BIND", v.clone()),
            (None, None) => ("--bind", DEFAULT_BIND.to_string()),
        };
        let bind: SocketAddr = bind_raw.parse().map_err(|_| {
            Localized::new("server.startup.bind_invalid")
                .var("source", bind_source)
                .var("value", bind_raw.as_str())
        })?;

        let data_dir = flags
            .data_dir
            .or_else(|| env.get("CYTRACE_DATA_DIR").map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from(DEFAULT_DATA_DIR));

        let db_cache_dir = env.get("GRYPE_DB_CACHE_DIR").map(PathBuf::from);

        let admin_password_hash = env
            .get("CYTRACE_ADMIN_PASSWORD_HASH")
            .cloned()
            .ok_or_else(|| Localized::new("server.startup.admin_hash_missing"))?;
        if !auth::is_valid_phc(&admin_password_hash) {
            return Err(Localized::new("server.startup.admin_hash_invalid"));
        }

        let admin_user = env
            .get("CYTRACE_ADMIN_USER")
            .cloned()
            .unwrap_or_else(|| "admin".into());

        let not_integer = |name: &'static str, raw: &str| {
            Localized::new("server.startup.not_integer")
                .var("name", name)
                .var("value", raw)
        };
        let ttl_hours = match env.get("CYTRACE_SESSION_TTL_HOURS") {
            Some(raw) => raw
                .parse::<u64>()
                .map_err(|_| not_integer("CYTRACE_SESSION_TTL_HOURS", raw))?,
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
            _ => return Err(Localized::new("server.startup.tls_unpaired")),
        };

        let scan_roots = match env.get("CYTRACE_SCAN_ROOTS") {
            Some(raw) => crate::targets::parse_roots(raw)?,
            None => Vec::new(),
        };

        let parse_usize = |key: &'static str, default: usize| -> Result<usize, Localized> {
            match env.get(key) {
                Some(raw) => raw.parse::<usize>().map_err(|_| not_integer(key, raw)),
                None => Ok(default),
            }
        };
        let max_concurrent_scans = parse_usize("CYTRACE_MAX_CONCURRENT_SCANS", 2)?.max(1);
        let max_queued = parse_usize("CYTRACE_MAX_QUEUED", 32)?.max(1);
        let keep_input = env
            .get("CYTRACE_KEEP_INPUT")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        let max_upload_bytes = parse_usize("CYTRACE_MAX_UPLOAD_MB", 512)? as u64 * 1024 * 1024;
        let max_extract_bytes = match env.get("CYTRACE_MAX_EXTRACT_MB") {
            Some(raw) => {
                raw.parse::<u64>()
                    .map_err(|_| not_integer("CYTRACE_MAX_EXTRACT_MB", raw))?
                    * 1024
                    * 1024
            }
            None => (max_upload_bytes.saturating_mul(10)).min(4 * 1024 * 1024 * 1024),
        };

        Ok(ServerConfig {
            bind,
            data_dir,
            db_cache_dir,
            admin_password_hash,
            admin_user,
            session_ttl,
            tls,
            scan_roots,
            max_concurrent_scans,
            max_queued,
            keep_input,
            max_upload_bytes,
            max_extract_bytes,
            lang: Lang::ZhTw,
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

    /// 以兩種語言渲染：不得殘留佔位符，且必須帶出實際的值。
    fn assert_renders(err: &Localized, must_contain: &str) {
        for lang in [Lang::ZhTw, Lang::EnUs] {
            let out = err.render(lang.catalog());
            assert!(!out.contains("{{"), "{lang:?} 殘留佔位符：{out}");
            assert!(
                out.contains(must_contain),
                "{lang:?} 應含 {must_contain}：{out}"
            );
        }
    }

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
        assert_eq!(err.key, "server.startup.bind_invalid");
        assert_eq!(
            err.vars,
            vec![
                ("source", "--bind".to_string()),
                ("value", "not-an-addr".to_string())
            ]
        );

        // 值來自環境變數時，訊息指名環境變數
        let err = ServerConfig::resolve(CliFlags::default(), env(&[("CYTRACE_BIND", "x:y")]))
            .unwrap_err();
        assert_eq!(
            err.vars,
            vec![
                ("source", "CYTRACE_BIND".to_string()),
                ("value", "x:y".to_string())
            ]
        );
    }

    #[test]
    fn admin_hash_required_and_validated() {
        // 缺失 → 拒絕啟動
        let err = ServerConfig::resolve(CliFlags::default(), HashMap::new()).unwrap_err();
        assert_eq!(err.key, "server.startup.admin_hash_missing");
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
        assert_eq!(err.key, "server.startup.admin_hash_invalid");
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
        assert_eq!(err.key, "server.startup.tls_unpaired");

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

    #[test]
    fn integer_and_scan_root_errors_name_the_variable() {
        for name in [
            "CYTRACE_SESSION_TTL_HOURS",
            "CYTRACE_MAX_CONCURRENT_SCANS",
            "CYTRACE_MAX_QUEUED",
            "CYTRACE_MAX_UPLOAD_MB",
            "CYTRACE_MAX_EXTRACT_MB",
        ] {
            let err =
                ServerConfig::resolve(CliFlags::default(), env(&[(name, "12x")])).unwrap_err();
            assert_eq!(err.key, "server.startup.not_integer", "{name}");
            assert_eq!(
                err.vars,
                vec![("name", name.to_string()), ("value", "12x".to_string())]
            );
            assert_renders(&err, name);
            assert_renders(&err, "12x");
        }

        let err = ServerConfig::resolve(CliFlags::default(), env(&[("CYTRACE_SCAN_ROOTS", "bad")]))
            .unwrap_err();
        assert_eq!(err.key, "server.startup.scan_roots_format");
        assert_eq!(err.vars, vec![("item", "bad".to_string())]);
        assert_renders(&err, "bad");
        let err = ServerConfig::resolve(
            CliFlags::default(),
            env(&[("CYTRACE_SCAN_ROOTS", "t=relative/p")]),
        )
        .unwrap_err();
        assert_eq!(err.key, "server.startup.scan_roots_not_absolute");
        assert_eq!(err.vars, vec![("item", "t=relative/p".to_string())]);
        assert_renders(&err, "t=relative/p");
    }
}
