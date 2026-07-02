//! Router 組裝（ADR-011 §7 API 表）。
//!
//! 疊層：CSRF guard（全域，變更型方法）→ auth middleware（受保護路由）。
//! 不掛任何 CORS layer——跨源 fetch 一律被瀏覽器擋（CSRF 第 3 層防禦）。

use crate::api;
use crate::auth;
use crate::config::ServerConfig;
use crate::error::{ApiError, ErrorKind, Lang};
use crate::state::AppState;
use axum::extract::State;
use axum::middleware;
use axum::routing::get;
use axum::{Json, Router};
use serde_json::{json, Value};

/// 組出完整 Router（供 `serve` 與 oneshot 整合測試共用）。
pub fn build_router(cfg: ServerConfig) -> Router {
    build_router_with_state(AppState::new(cfg))
}

/// 以既有 state 組 Router（測試可注入自訂 throttle/sessions）。
pub fn build_router_with_state(state: AppState) -> Router {
    // 公開：liveness 與登入（登入受節流保護；仍在 CSRF guard 之內）
    let public = Router::new()
        .route("/healthz", get(healthz))
        .route("/api/v1/session", axum::routing::post(api::session::login));

    // 受保護：一切業務 API（jobs/reports 隨 T804–T805 增補）
    let protected = Router::new()
        .route("/api/v1/version", get(version))
        .route(
            "/api/v1/session",
            get(api::session::whoami).delete(api::session::logout),
        )
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::require_session,
        ));

    public
        .merge(protected)
        .fallback(fallback)
        .layer(middleware::from_fn(auth::csrf_guard))
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
