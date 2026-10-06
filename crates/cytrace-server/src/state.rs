//! 共享應用狀態。handlers 跑在任意 thread（axum/tokio）——一律 `Arc`（Send + Sync）。

use crate::auth::LoginThrottle;
use crate::config::ServerConfig;
use crate::jobs::registry::JobRegistry;
use crate::session::SessionStore;
use cytrace_core::engine::{RealEngine, ScanEngine};
use cytrace_i18n::Localized;
use std::sync::Arc;
use tokio::sync::Semaphore;

/// axum `State` extractor 的共享狀態。
#[derive(Clone)]
pub struct AppState {
    pub cfg: Arc<ServerConfig>,
    pub sessions: Arc<SessionStore>,
    pub throttle: Arc<LoginThrottle>,
    pub engine: Arc<dyn ScanEngine>,
    pub jobs: Arc<JobRegistry>,
    pub scan_semaphore: Arc<Semaphore>,
    pub hooks: Hooks,
}

/// 在指定時間點插入動作的 hook（參數：狀態、job id）。
#[doc(hidden)]
pub type Hook = Arc<dyn Fn(&AppState, &str) + Send + Sync>;

/// 競態測試用的時間點注入（整合測試用，同 [`AppState::with_engine`] 的引擎注入）。
/// 生產環境一律為空（`Default`），不改變任何行為。
#[doc(hidden)]
#[derive(Clone, Default)]
pub struct Hooks {
    /// DELETE 讀到 queued 之後、嘗試取消之前（#42：模擬 runner 在這個空檔搶先開始掃描）。
    pub before_cancel: Option<Hook>,
}

impl AppState {
    /// 真實引擎（子程序呼叫 syft/grype）。開啟 data_dir 失敗（不可寫等）→ 啟動錯誤。
    pub fn new(cfg: ServerConfig) -> Result<Self, Localized> {
        Self::with_engine(cfg, Arc::new(RealEngine))
    }

    /// 注入引擎（整合測試用 fake，免 syft/grype binary）。
    pub fn with_engine(cfg: ServerConfig, engine: Arc<dyn ScanEngine>) -> Result<Self, Localized> {
        let sessions = Arc::new(SessionStore::new(cfg.session_ttl));
        let jobs = Arc::new(JobRegistry::open(&cfg.data_dir, cfg.lang)?);
        if !cfg.keep_input {
            jobs.purge_inputs();
        }
        let scan_semaphore = Arc::new(Semaphore::new(cfg.max_concurrent_scans));
        Ok(AppState {
            cfg: Arc::new(cfg),
            sessions,
            throttle: Arc::new(LoginThrottle::default()),
            engine,
            jobs,
            scan_semaphore,
            hooks: Hooks::default(),
        })
    }

    /// 注入競態測試用的時間點 hook。
    #[doc(hidden)]
    pub fn with_hooks(mut self, hooks: Hooks) -> Self {
        self.hooks = hooks;
        self
    }
}
