//! Router 整合測試（`tower::ServiceExt::oneshot`，不開真實 socket、不需引擎 binary）。

use axum::body::Body;
use axum::http::{Request, StatusCode};
use cytrace_server::config::ServerConfig;
use cytrace_server::router::build_router;
use http_body_util::BodyExt;
use tower::util::ServiceExt;

fn test_config() -> ServerConfig {
    ServerConfig::resolve(
        Some("127.0.0.1:0".into()),
        None,
        std::collections::HashMap::new(),
    )
    .expect("test config 應合法")
}

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn healthz_returns_ok_without_auth() {
    let app = build_router(test_config());
    let resp = app
        .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&bytes[..], b"ok");
}

#[tokio::test]
async fn version_reports_cytrace_and_db_status() {
    let app = build_router(test_config());
    let resp = app
        .oneshot(Request::get("/api/v1/version").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp).await;
    assert_eq!(v["cytrace"], env!("CARGO_PKG_VERSION"));
    // 測試環境無 grype DB → degraded 回報 absent（ADR-012 C3 護欄）
    assert_eq!(v["db"]["present"], false);
}

#[tokio::test]
async fn unknown_route_returns_404_error_shape() {
    let app = build_router(test_config());
    let resp = app
        .oneshot(Request::get("/api/v1/no-such").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let v = body_json(resp).await;
    assert_eq!(v["error"]["kind"], "not_found");
    assert_eq!(v["error"]["i18n_key"], "server.err.not_found");
    // message 必須走 locales（zh-TW fallback），不可是英文硬編碼
    assert!(v["error"]["message"].as_str().unwrap() != "server.err.not_found");
}

#[tokio::test]
async fn lang_negotiation_switches_error_language() {
    let app = build_router(test_config());
    let resp = app
        .oneshot(
            Request::get("/api/v1/no-such?lang=en-US")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let v = body_json(resp).await;
    assert_eq!(v["error"]["message"], "Resource not found");

    let app = build_router(test_config());
    let resp = app
        .oneshot(Request::get("/api/v1/no-such").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let v = body_json(resp).await;
    assert_eq!(v["error"]["message"], "找不到資源");
}
