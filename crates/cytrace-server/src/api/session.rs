//! Session API：登入 / 會話資訊 / 登出（ADR-011 §3–4）。

use crate::auth;
use crate::error::{ApiError, ErrorKind, Lang};
use crate::session::{login_cookie, logout_cookie, token_from_cookie_header};
use crate::state::AppState;
use axum::extract::{ConnectInfo, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use cytrace_core::timefmt::epoch_to_iso;
use serde::Deserialize;
use serde_json::json;
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Deserialize)]
pub struct LoginBody {
    password: String,
}

fn iso_of(t: SystemTime) -> String {
    epoch_to_iso(
        t.duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    )
}

/// `POST /api/v1/session`：登入。成功 204 + Set-Cookie；失敗統一 401（單帳號無枚舉問題）。
pub async fn login(
    State(app): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    lang: Lang,
    Json(body): Json<LoginBody>,
) -> Result<Response, ApiError> {
    let ip = peer.ip();
    if let Err(retry) = app.throttle.check(ip) {
        return Err(ApiError::new(lang, ErrorKind::RateLimited).with_retry_after(retry));
    }
    let ok = auth::verify_password(&body.password, &app.cfg.admin_password_hash)
        .map_err(|e| ApiError::new(lang, ErrorKind::Internal).with_detail(e.to_string()))?;
    if !ok {
        app.throttle.record_failure(ip);
        return Err(ApiError::new(lang, ErrorKind::Auth));
    }
    let token = app
        .sessions
        .create()
        .map_err(|e| ApiError::new(lang, ErrorKind::Internal).with_detail(e.to_string()))?;
    let cookie = login_cookie(&token, app.cfg.tls.is_some());
    Ok((StatusCode::NO_CONTENT, [(header::SET_COOKIE, cookie)]).into_response())
}

/// `GET /api/v1/session`：會話資訊（受 auth middleware 保護，到這裡必有合法 session）。
pub async fn whoami(
    State(app): State<AppState>,
    lang: Lang,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    let session = headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(token_from_cookie_header)
        .and_then(|t| app.sessions.validate(t))
        .ok_or_else(|| ApiError::new(lang, ErrorKind::Auth))?;
    Ok(Json(json!({
        "user": app.cfg.admin_user,
        "created_at": iso_of(session.created_at),
        "expires_at": iso_of(session.expires_at),
    })))
}

/// `DELETE /api/v1/session`：登出（冪等）。
pub async fn logout(State(app): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(token) = headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(token_from_cookie_header)
    {
        app.sessions.revoke(token);
    }
    (
        StatusCode::NO_CONTENT,
        [(header::SET_COOKIE, logout_cookie(app.cfg.tls.is_some()))],
    )
        .into_response()
}
