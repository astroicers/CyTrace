//! Router 組裝（ADR-011 §7 API 表）。
//!
//! 疊層：CSRF guard（全域，變更型方法）→ auth middleware（受保護路由）。
//! 不掛任何 CORS layer——跨源 fetch 一律被瀏覽器擋（CSRF 第 3 層防禦）。

use crate::api;
use crate::auth;
use crate::config::ServerConfig;
use crate::error::{ApiError, ErrorKind, Lang};
use crate::state::AppState;
use crate::static_files;
use axum::extract::State;
use axum::http::{header, HeaderValue, Request};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde_json::{json, Value};

/// 組出完整 Router（供 `serve` 與 oneshot 整合測試共用）。
pub fn build_router(cfg: ServerConfig) -> anyhow::Result<Router> {
    Ok(build_router_with_state(AppState::new(cfg)?))
}

/// 以既有 state 組 Router（測試可注入自訂 throttle/sessions）。
pub fn build_router_with_state(state: AppState) -> Router {
    // 公開：liveness 與登入（登入受節流保護；仍在 CSRF guard 之內）
    let public = Router::new()
        .route("/healthz", get(healthz))
        .route("/api/v1/session", axum::routing::post(api::session::login));

    // 受保護：一切業務 API（reports 隨 T805 增補）
    let protected = Router::new()
        .route("/api/v1/version", get(version))
        .route(
            "/api/v1/session",
            get(api::session::whoami).delete(api::session::logout),
        )
        .route("/api/v1/targets", get(api::jobs::targets_list))
        .route("/api/v1/jobs", get(api::jobs::list).post(api::jobs::create))
        .route(
            "/api/v1/jobs/upload",
            axum::routing::post(api::jobs::upload),
        )
        .route(
            "/api/v1/jobs/{id}",
            get(api::jobs::get).delete(api::jobs::delete),
        )
        .route("/api/v1/jobs/{id}/report", get(api::reports::report))
        .route("/api/v1/jobs/{id}/result", get(api::reports::result))
        .route(
            "/api/v1/jobs/{id}/artifacts/{kind}",
            get(api::reports::artifact),
        )
        // 路徑命中、方法不符 → JSON 405（原本是 axum 預設的空 body，繞過錯誤契約與語系；
        // T909 第二輪複審 claims#4）。必須在 auth layer **之前**設：之後設會換掉已被 auth
        // 包住的 fallback，未登入者就會拿到 405 而非 401。public 那條 /api/v1/session 與本處
        // 的同路徑 method router 合併時沿用這裡的 fallback。
        .method_not_allowed_fallback(method_not_allowed)
        .layer(axum::extract::DefaultBodyLimit::disable()) // 上傳大小由 handler 串流計數把關
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::require_session,
        ));

    public
        .merge(protected)
        .fallback(fallback) // 未命中：/api/* → JSON 404；其餘 → console SPA
        .layer(middleware::from_fn(auth::csrf_guard))
        .layer(middleware::from_fn(security_headers))
        .with_state(state)
}

/// 安全標頭：console CSP（connect-src 'self'）+ 常規硬化（ADR-011 §6）。
/// 報表端點自帶 meta CSP（connect-src 'none'），不受此層影響（HTTP header 與 meta 併存，較嚴者生效）。
async fn security_headers(req: Request<axum::body::Body>, next: Next) -> Response {
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    // 只在 handler 未自設 CSP 時填 console CSP——報表端點自帶較寬的 CSP
    // （需 script-src 'unsafe-inline' 給 singlefile 內聯腳本），不可被此處覆蓋。
    if !h.contains_key(header::CONTENT_SECURITY_POLICY) {
        h.insert(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(
                "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; \
                 img-src 'self' data:; font-src 'self'; connect-src 'self'; \
                 form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
            ),
        );
    }
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    );
    resp
}

/// liveness（無 auth、不洩漏版本；容器 healthcheck 由 `cytrace health` TCP 檢查搭配）。
async fn healthz() -> &'static str {
    "ok"
}

/// 版本與 DB 快照狀態（ADR-012 C3：DB 缺失 degraded 回報，CI 冒煙依賴此行為）。
async fn version(State(app): State<AppState>) -> Json<Value> {
    let roots: Vec<&str> = app.cfg.scan_roots.iter().map(|(n, _)| n.as_str()).collect();
    Json(json!({
        "cytrace": env!("CARGO_PKG_VERSION"),
        "db": { "present": app.cfg.db_present() },
        "upload_limit_mb": app.cfg.max_upload_bytes / (1024 * 1024),
        "scan_roots": roots,
    }))
}

/// 路徑命中、方法不符：JSON 405（axum 仍會附上 `Allow` header）。
async fn method_not_allowed(lang: Lang) -> Response {
    ApiError::new(lang, ErrorKind::MethodNotAllowed).into_response()
}

/// 未命中路由：`/api/*`、`/healthz` → JSON 404；其餘（`/`、`/assets/*`）→ console SPA。
async fn fallback(lang: Lang, uri: axum::http::Uri) -> Response {
    let path = uri.path();
    if path.starts_with("/api/") || path == "/healthz" {
        ApiError::new(lang, ErrorKind::NotFound).into_response()
    } else {
        static_files::console_spa(uri).await
    }
}
