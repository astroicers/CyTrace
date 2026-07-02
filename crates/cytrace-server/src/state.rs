//! 共享應用狀態。handlers 跑在任意 thread（axum/tokio）——一律 `Arc`（Send + Sync）。

use crate::auth::LoginThrottle;
use crate::config::ServerConfig;
use crate::session::SessionStore;
use std::sync::Arc;

/// axum `State` extractor 的共享狀態（jobs registry 隨 T804 增補）。
#[derive(Clone)]
pub struct AppState {
    pub cfg: Arc<ServerConfig>,
    pub sessions: Arc<SessionStore>,
    pub throttle: Arc<LoginThrottle>,
}

impl AppState {
    pub fn new(cfg: ServerConfig) -> Self {
        let sessions = Arc::new(SessionStore::new(cfg.session_ttl));
        AppState {
            cfg: Arc::new(cfg),
            sessions,
            throttle: Arc::new(LoginThrottle::default()),
        }
    }
}
