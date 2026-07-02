//! Router 整合測試（`tower::ServiceExt::oneshot`，不開真實 socket、不需引擎 binary）。

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{header, Request, StatusCode};
use axum::Router;
use cytrace_server::auth::{hash_password, CSRF_HEADER};
use cytrace_server::config::{CliFlags, ServerConfig};
use cytrace_server::router::build_router;
use http_body_util::BodyExt;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::LazyLock;
use tower::util::ServiceExt;

const TEST_PASSWORD: &str = "test-password-123";
static TEST_PHC: LazyLock<String> = LazyLock::new(|| hash_password(TEST_PASSWORD).unwrap());

fn test_config_with(extra_env: &[(&str, &str)]) -> ServerConfig {
    let mut env: HashMap<String, String> = extra_env
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    env.insert("CYTRACE_ADMIN_PASSWORD_HASH".into(), TEST_PHC.clone());
    ServerConfig::resolve(
        CliFlags {
            bind: Some("127.0.0.1:0".into()),
            ..Default::default()
        },
        env,
    )
    .expect("test config 應合法")
}

fn app() -> Router {
    build_router(test_config_with(&[]))
}

fn peer(n: u8) -> ConnectInfo<SocketAddr> {
    ConnectInfo(SocketAddr::from(([10, 0, 0, n], 55555)))
}

fn login_request(password: &str, ip: u8) -> Request<Body> {
    let mut req = Request::post("/api/v1/session")
        .header(header::CONTENT_TYPE, "application/json")
        .header(CSRF_HEADER, "1")
        .body(Body::from(format!("{{\"password\":\"{password}\"}}")))
        .unwrap();
    req.extensions_mut().insert(peer(ip));
    req
}

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

/// 登入拿 cookie（成功路徑的共用起手式）。
async fn login_cookie_value(app: &Router) -> String {
    let resp = app
        .clone()
        .oneshot(login_request(TEST_PASSWORD, 1))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let set_cookie = resp
        .headers()
        .get(header::SET_COOKIE)
        .expect("登入成功應回 Set-Cookie")
        .to_str()
        .unwrap();
    set_cookie.split(';').next().unwrap().to_string()
}

// ─── 基礎路由 ───

#[tokio::test]
async fn healthz_is_public() {
    let resp = app()
        .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn unknown_route_returns_404_error_shape() {
    let resp = app()
        .oneshot(Request::get("/api/v1/no-such").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let v = body_json(resp).await;
    assert_eq!(v["error"]["kind"], "not_found");
    assert_eq!(v["error"]["i18n_key"], "server.err.not_found");
}

#[tokio::test]
async fn lang_negotiation_switches_error_language() {
    let resp = app()
        .oneshot(
            Request::get("/api/v1/no-such?lang=en-US")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        body_json(resp).await["error"]["message"],
        "Resource not found"
    );

    let resp = app()
        .oneshot(Request::get("/api/v1/no-such").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(body_json(resp).await["error"]["message"], "找不到資源");
}

// ─── 認證 ───

#[tokio::test]
async fn version_requires_auth() {
    let app = app();
    let resp = app
        .clone()
        .oneshot(Request::get("/api/v1/version").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let v = body_json(resp).await;
    assert_eq!(v["error"]["kind"], "auth");

    let cookie = login_cookie_value(&app).await;
    let resp = app
        .oneshot(
            Request::get("/api/v1/version")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp).await;
    assert_eq!(v["cytrace"], env!("CARGO_PKG_VERSION"));
    assert_eq!(v["db"]["present"], false);
}

#[tokio::test]
async fn login_wrong_password_returns_401_uniform() {
    let resp = app()
        .oneshot(login_request("wrong-password-xx", 2))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let v = body_json(resp).await;
    assert_eq!(v["error"]["kind"], "auth");
}

#[tokio::test]
async fn whoami_and_logout_lifecycle() {
    let app = app();
    let cookie = login_cookie_value(&app).await;

    // whoami
    let resp = app
        .clone()
        .oneshot(
            Request::get("/api/v1/session")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp).await;
    assert_eq!(v["user"], "admin");
    assert!(v["expires_at"].as_str().unwrap().ends_with('Z'));

    // logout（冪等、清 cookie）
    let resp = app
        .clone()
        .oneshot(
            Request::delete("/api/v1/session")
                .header(header::COOKIE, &cookie)
                .header(CSRF_HEADER, "1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert!(resp
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .contains("Max-Age=0"));

    // 登出後 session 失效
    let resp = app
        .oneshot(
            Request::get("/api/v1/session")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn session_ttl_zero_expires_immediately() {
    let app = build_router(test_config_with(&[("CYTRACE_SESSION_TTL_HOURS", "0")]));
    let cookie = {
        let resp = app
            .clone()
            .oneshot(login_request(TEST_PASSWORD, 3))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        resp.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string()
    };
    let resp = app
        .oneshot(
            Request::get("/api/v1/session")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ─── 節流 ───

#[tokio::test]
async fn login_throttled_after_five_failures_per_ip() {
    let app = app();
    for _ in 0..5 {
        let resp = app
            .clone()
            .oneshot(login_request("wrong-password-xx", 7))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
    let resp = app
        .clone()
        .oneshot(login_request(TEST_PASSWORD, 7))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(resp.headers().contains_key(header::RETRY_AFTER));
    // 其他 IP 不受影響
    let resp = app.oneshot(login_request(TEST_PASSWORD, 8)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

// ─── CSRF ───

#[tokio::test]
async fn mutating_request_without_csrf_header_is_403() {
    let mut req = Request::post("/api/v1/session")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(format!("{{\"password\":\"{TEST_PASSWORD}\"}}")))
        .unwrap();
    req.extensions_mut().insert(peer(9));
    let resp = app().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let v = body_json(resp).await;
    assert_eq!(v["error"]["kind"], "csrf");
}

#[tokio::test]
async fn get_requests_do_not_need_csrf_header() {
    let resp = app()
        .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

// ─── Cookie 屬性 ───

#[tokio::test]
async fn cookie_attributes_hardened() {
    let resp = app()
        .oneshot(login_request(TEST_PASSWORD, 11))
        .await
        .unwrap();
    let cookie = resp.headers()[header::SET_COOKIE].to_str().unwrap();
    assert!(cookie.contains("HttpOnly"));
    assert!(cookie.contains("SameSite=Strict"));
    // 無 TLS 設定 → 不加 Secure（HTTP 測試環境）
    assert!(!cookie.contains("Secure"));
}
