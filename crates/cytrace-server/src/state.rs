//! 共享應用狀態。handlers 跑在任意 thread（axum/tokio）——一律 `Arc`（Send + Sync）。

use crate::auth::LoginThrottle;
use crate::config::ServerConfig;
use crate::jobs::registry::JobRegistry;
use crate::session::SessionStore;
use cytrace_core::engine::{RealEngine, ScanEngine};
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
}

impl AppState {
    /// 真實引擎（子程序呼叫 syft/grype）。開啟 data_dir 失敗（不可寫等）→ 啟動錯誤。
    pub fn new(cfg: ServerConfig) -> anyhow::Result<Self> {
        Self::with_engine(cfg, Arc::new(RealEngine))
    }

    /// 注入引擎（整合測試用 fake，免 syft/grype binary）。
    pub fn with_engine(cfg: ServerConfig, engine: Arc<dyn ScanEngine>) -> anyhow::Result<Self> {
        let sessions = Arc::new(SessionStore::new(cfg.session_ttl));
        let jobs = Arc::new(JobRegistry::open(&cfg.data_dir)?);
        let scan_semaphore = Arc::new(Semaphore::new(cfg.max_concurrent_scans));
        Ok(AppState {
            cfg: Arc::new(cfg),
            sessions,
            throttle: Arc::new(LoginThrottle::default()),
            engine,
            jobs,
            scan_semaphore,
        })
    }
}
