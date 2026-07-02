//! Router 組裝（ADR-011 §7 API 表）。middleware 疊層（body limit → auth → csrf）隨 T803 掛上。

use crate::config::ServerConfig;
use crate::error::{ApiError, ErrorKind, Lang};
use crate::state::AppState;
use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use serde_json::{json, Value};

/// 組出完整 Router（供 `serve` 與 oneshot 整合測試共用）。
pub fn build_router(cfg: ServerConfig) -> Router {
    let state = AppState::new(cfg);
    Router::new()
        .route("/healthz", get(healthz))
        .route("/api/v1/version", get(version))
        .fallback(fallback)
        .with_state(state)
}

/// liveness（無 auth、不洩漏版本；容器 healthcheck 由 `cytrace health` TCP 檢查搭配）。
async fn healthz() -> &'static str {
    "ok"
}

/// 版本與 DB 快照狀態（ADR-012 C3：DB 缺失 degraded 回報，CI 冒煙依賴此行為）。
async fn version(State(app): State<AppState>) -> Json<Value> {
    Json(json!({
        "cytrace": env!("CARGO_PKG_VERSION"),
        "db": { "present": app.cfg.db_present() },
    }))
}

async fn fallback(lang: Lang) -> ApiError {
    ApiError::new(lang, ErrorKind::NotFound)
}
