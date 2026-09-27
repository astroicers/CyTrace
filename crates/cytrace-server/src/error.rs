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
    ForbiddenPath,
    Conflict,
    QueueFull,
    PayloadTooLarge,
    UnsupportedArchive,
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
            ErrorKind::ForbiddenPath => "forbidden_path",
            ErrorKind::Conflict => "conflict",
            ErrorKind::QueueFull => "queue_full",
            ErrorKind::PayloadTooLarge => "payload_too_large",
            ErrorKind::UnsupportedArchive => "unsupported_archive",
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
            ErrorKind::ForbiddenPath => StatusCode::FORBIDDEN,
            ErrorKind::Conflict => StatusCode::CONFLICT,
            ErrorKind::QueueFull => StatusCode::TOO_MANY_REQUESTS,
            ErrorKind::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            ErrorKind::UnsupportedArchive => StatusCode::UNSUPPORTED_MEDIA_TYPE,
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

    /// CytraceError → ApiError 對映（Engine/Parse/Io/Config/DbMissing/Cbom）。
    ///
    /// **目前無生產呼叫者**：job 執行緒的 CBOM 失敗全部落在 `CbomStatus` 裡
    /// （`collect_cbom` 依設計永不回 `Err`），SBOM/CVE 失敗由 runner 自行記錄。
    /// 保留本對映是為了 handler 日後直接回傳 core error 時有一致出口；因為無人呼叫，
    /// 它也從未被驗證過（第六輪複審 minor），故下方測試逐變體釘住 kind、狀態碼與
    /// **detail 不得為裸 i18n 鍵**。
    pub fn from_core(lang: Lang, err: &CytraceError) -> Self {
        let kind = match err {
            CytraceError::Engine(_) => ErrorKind::Engine,
            CytraceError::Parse(_) => ErrorKind::Parse,
            CytraceError::Io(_) => ErrorKind::Io,
            CytraceError::Config(_) => ErrorKind::Config,
            CytraceError::DbMissing(_) => ErrorKind::DbMissing,
            // CBOM 引擎失敗歸引擎類（掃描整體仍可完成，只是 crypto 區段缺）
            CytraceError::Cbom { .. } => ErrorKind::Engine,
        };
        // Cbom 的 Display 是「鍵：細節」——直接當 detail 就是把裸鍵送出 API。
        // 改以請求語系渲染，與 CLI 共用 Catalog::render_cbom（單一實作）。
        //
        // 其餘變體的 Display 各帶一段中文前綴（「引擎子程序錯誤：」…），直接當 detail
        // 會讓 `--lang en-US` 的 API 回應夾中文（第七輪複審：與 collect_cbom 同一種錯法，
        // 只是位置在 server）。故一律走 CytraceError::untranslatable_detail。
        let detail = match err {
            CytraceError::Cbom { key, detail } => {
                Some(lang.catalog().render_cbom(key, detail.as_deref()))
            }
            other => other.untranslatable_detail(),
        };
        let api = ApiError::new(lang, kind);
        match detail {
            Some(d) => api.with_detail(d),
            None => api,
        }
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
        let e = ApiError::from_core(Lang::ZhTw, &CytraceError::Parse("x".into()));
        assert_eq!(e.kind, ErrorKind::Parse);
        let e = ApiError::from_core(Lang::ZhTw, &CytraceError::Config("x".into()));
        assert_eq!(e.kind, ErrorKind::Config);
    }

    #[test]
    fn cbom_error_detail_is_translated_not_a_bare_key() {
        // Cbom 的 Display 是「鍵：細節」；若直接當 detail，API 消費者收到的是裸鍵。
        let err = CytraceError::Cbom {
            key: "cbom.err.timeout",
            detail: Some("600".into()),
        };
        for lang in [Lang::ZhTw, Lang::EnUs] {
            let e = ApiError::from_core(lang, &err);
            assert_eq!(e.kind, ErrorKind::Engine, "CBOM 失敗歸引擎類");
            let d = e.detail.as_deref().expect("應帶 detail");
            assert!(
                !d.contains("cbom.err."),
                "detail 不得含裸 i18n 鍵，實為 {d}"
            );
            assert!(!d.contains("{{"), "detail 不得殘留佔位符，實為 {d}");
            assert!(d.contains("600"), "逾時秒數須插值進訊息，實為 {d}");
        }
    }

    #[test]
    fn cbom_error_detail_follows_request_language() {
        let err = CytraceError::Cbom {
            key: "cbom.err.target_not_archive",
            detail: Some("/tmp/firmware.bin".into()),
        };
        let zh = ApiError::from_core(Lang::ZhTw, &err).detail.unwrap();
        let en = ApiError::from_core(Lang::EnUs, &err).detail.unwrap();
        assert_ne!(zh, en, "兩語系訊息不得相同（否則等於沒吃 lang）");
        // en-US 不得夾中日韓字元（英文文案含破折號等非 ASCII 標點屬正常）
        assert!(
            !en.chars().any(|c| matches!(c as u32,
                0x4E00..=0x9FFF | 0x3000..=0x303F | 0xFF00..=0xFFEF)),
            "en-US 訊息不得含中文字元或全角標點，實為 {en}"
        );
        assert!(zh.contains("/tmp/firmware.bin") && en.contains("/tmp/firmware.bin"));
    }
}
