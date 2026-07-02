//! API 錯誤：CytraceError 分類 → HTTP 狀態 + i18n 鍵（ADR-011 §7 錯誤格式）。
//!
//! 回應形：`{"error":{"kind","i18n_key","message","detail"}}`——`message` 依請求協商
//! 語言由 [`Catalog`] 產生（禁硬編碼，NFR-06）；catalog 為程序級常量（內嵌 locales）。

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use cytrace_core::error::CytraceError;
use cytrace_i18n::Catalog;
use serde_json::json;
use std::sync::LazyLock;

static ZH: LazyLock<Catalog> = LazyLock::new(|| Catalog::load("zh-TW"));
static EN: LazyLock<Catalog> = LazyLock::new(|| Catalog::load("en-US"));

/// 請求協商語言（`?lang=` > `Accept-Language` > zh-TW，與 CLI 優先序一致）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    ZhTw,
    EnUs,
}

impl Lang {
    pub fn catalog(self) -> &'static Catalog {
        match self {
            Lang::ZhTw => &ZH,
            Lang::EnUs => &EN,
        }
    }

    fn from_code(code: &str) -> Lang {
        if code.trim().to_ascii_lowercase().starts_with("en") {
            Lang::EnUs
        } else {
            Lang::ZhTw
        }
    }

    /// 由 query string 與 Accept-Language 標頭協商。
    pub fn negotiate(query: Option<&str>, accept_language: Option<&str>) -> Lang {
        if let Some(q) = query {
            for pair in q.split('&') {
                if let Some(v) = pair.strip_prefix("lang=") {
                    return Lang::from_code(v);
                }
            }
        }
        if let Some(al) = accept_language {
            if let Some(first) = al.split(',').next() {
                return Lang::from_code(first);
            }
        }
        Lang::ZhTw
    }
}

impl<S: Send + Sync> FromRequestParts<S> for Lang {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let al = parts
            .headers
            .get(axum::http::header::ACCEPT_LANGUAGE)
            .and_then(|v| v.to_str().ok());
        Ok(Lang::negotiate(parts.uri.query(), al))
    }
}

/// 錯誤類別（CytraceError 5 類 + server 專屬類；隨 T804–T805 增補）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    Engine,
    Parse,
    Io,
    Config,
    DbMissing,
    NotFound,
    Internal,
    Auth,
    Csrf,
    RateLimited,
    Validation,
}

impl ErrorKind {
    fn as_str(self) -> &'static str {
        match self {
            ErrorKind::Engine => "engine",
            ErrorKind::Parse => "parse",
            ErrorKind::Io => "io",
            ErrorKind::Config => "config",
            ErrorKind::DbMissing => "db_missing",
            ErrorKind::NotFound => "not_found",
            ErrorKind::Internal => "internal",
            ErrorKind::Auth => "auth",
            ErrorKind::Csrf => "csrf",
            ErrorKind::RateLimited => "rate_limited",
            ErrorKind::Validation => "validation",
        }
    }

    fn status(self) -> StatusCode {
        match self {
            ErrorKind::NotFound => StatusCode::NOT_FOUND,
            ErrorKind::DbMissing => StatusCode::SERVICE_UNAVAILABLE,
            ErrorKind::Auth => StatusCode::UNAUTHORIZED,
            ErrorKind::Csrf => StatusCode::FORBIDDEN,
            ErrorKind::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            ErrorKind::Validation => StatusCode::BAD_REQUEST,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn i18n_key(self) -> String {
        format!("server.err.{}", self.as_str())
    }
}

/// API 錯誤。`detail` 是給稽核/除錯的原始資訊（不翻譯）；`message` 走 locales。
#[derive(Debug)]
pub struct ApiError {
    pub lang: Lang,
    pub kind: ErrorKind,
    pub detail: Option<String>,
    /// 429 時的 `Retry-After` 秒數。
    pub retry_after: Option<u64>,
}

impl ApiError {
    pub fn new(lang: Lang, kind: ErrorKind) -> Self {
        ApiError {
            lang,
            kind,
            detail: None,
            retry_after: None,
        }
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    pub fn with_retry_after(mut self, secs: u64) -> Self {
        self.retry_after = Some(secs);
        self
    }

    /// CytraceError → ApiError 對映（Engine/Parse/Io/Config/DbMissing）。
    pub fn from_core(lang: Lang, err: &CytraceError) -> Self {
        let kind = match err {
            CytraceError::Engine(_) => ErrorKind::Engine,
            CytraceError::Parse(_) => ErrorKind::Parse,
            CytraceError::Io(_) => ErrorKind::Io,
            CytraceError::Config(_) => ErrorKind::Config,
            CytraceError::DbMissing(_) => ErrorKind::DbMissing,
        };
        ApiError::new(lang, kind).with_detail(err.to_string())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let key = self.kind.i18n_key();
        let message = self.lang.catalog().t(&key, &[]);
        let body = json!({
            "error": {
                "kind": self.kind.as_str(),
                "i18n_key": key,
                "message": message,
                "detail": self.detail,
            }
        });
        let mut resp = (self.kind.status(), Json(body)).into_response();
        if let Some(secs) = self.retry_after {
            if let Ok(v) = axum::http::HeaderValue::from_str(&secs.to_string()) {
                resp.headers_mut()
                    .insert(axum::http::header::RETRY_AFTER, v);
            }
        }
        resp
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negotiate_prefers_query_over_header() {
        assert_eq!(
            Lang::negotiate(Some("lang=en-US"), Some("zh-TW")),
            Lang::EnUs
        );
        assert_eq!(Lang::negotiate(None, Some("en-US,en;q=0.9")), Lang::EnUs);
        assert_eq!(Lang::negotiate(None, None), Lang::ZhTw);
        assert_eq!(Lang::negotiate(Some("foo=1&lang=en"), None), Lang::EnUs);
    }

    #[test]
    fn core_error_maps_to_kind() {
        let e = ApiError::from_core(Lang::ZhTw, &CytraceError::Engine("x".into()));
        assert_eq!(e.kind, ErrorKind::Engine);
        assert_eq!(e.kind.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let e = ApiError::from_core(Lang::ZhTw, &CytraceError::DbMissing("x".into()));
        assert_eq!(e.kind.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
