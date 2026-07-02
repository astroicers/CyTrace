//! 共享應用狀態。handlers 跑在任意 thread（axum/tokio）——一律 `Arc`（Send + Sync）。

use crate::config::ServerConfig;
use std::sync::Arc;

/// axum `State` extractor 的共享狀態（session store / jobs registry 隨 T803/T804 增補）。
#[derive(Clone)]
pub struct AppState {
    pub cfg: Arc<ServerConfig>,
}

impl AppState {
    pub fn new(cfg: ServerConfig) -> Self {
        AppState { cfg: Arc::new(cfg) }
    }
}
