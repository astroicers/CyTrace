//! 包裝 axum extractor：解析失敗一律走本專案的 JSON 錯誤格式（ADR-011 §7）並依請求語系渲染。
//!
//! axum 內建的 `Json` / `Query` / `Path` / `Multipart` 解析失敗時，直接回**英文純文字**
//! （`Failed to deserialize the JSON body…`）——完全繞過 [`ApiError`]：zh-TW 用戶端收到英文、
//! console 的 client 解不出 `{"error":{…}}` 而退回泛用訊息（T909 分類 workflow 反向追蹤發現）。
//!
//! handler 一律用本模組的型別取代 axum 原生 extractor；回應的 JSON 用 [`JsonOut`]。
//! 回退由 clippy `disallowed-types`（workspace `clippy.toml`）擋住——`Path`/`Query`/`Multipart`/
//! `Json`/`ConnectInfo` 全列。clippy 看的是**解析後的型別**，別名（含分組 `use`）、
//! `extract::Json`、`type` 別名、closure handler、跨檔 re-export 都繞不過。
//!
//! `Json` 原本因為「同時是回應型別」而沒列，改由一支簽名級文字閘把關——兩輪複審各找到一批
//! 繞過寫法（第二輪 claims#3、第三輪 server#0），列舉寫法的文字比對永遠追不完。回應改用
//! [`JsonOut`] 之後就能全面禁用。合法的裸用處（本模組、`ConnectInfo` 的登入節流）各自以
//! `#[allow]` 附理由豁免。

// 本模組是 axum 原生 extractor 唯一的合法使用處（clippy.toml disallowed-types）
#![allow(clippy::disallowed_types)]

use crate::error::{bad_request, ApiError, Lang};
use axum::extract::{FromRequest, FromRequestParts, Multipart, Path, Query, Request};
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use axum::Json;

/// 從 request parts 協商語系（與 [`Lang`] 的 extractor 同一規則：`?lang=` > `Accept-Language`）。
fn lang_of(parts: &Parts) -> Lang {
    let al = parts
        .headers
        .get(axum::http::header::ACCEPT_LANGUAGE)
        .and_then(|v| v.to_str().ok());
    Lang::negotiate(parts.uri.query(), al)
}

/// `Json<T>` 的包裝：解析失敗 → `ApiError(Validation, server.err.bad_request)`。
pub struct ApiJson<T>(pub T);

impl<T, S> FromRequest<S> for ApiJson<T>
where
    Json<T>: FromRequest<S, Rejection = axum::extract::rejection::JsonRejection>,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let (parts, body) = req.into_parts();
        let lang = lang_of(&parts);
        let req = Request::from_parts(parts, body);
        Json::<T>::from_request(req, state)
            .await
            .map(|Json(v)| ApiJson(v))
            .map_err(|r| bad_request(lang, r))
    }
}

/// `Query<T>` 的包裝。
pub struct ApiQuery<T>(pub T);

impl<T, S> FromRequestParts<S> for ApiQuery<T>
where
    Query<T>: FromRequestParts<S, Rejection = axum::extract::rejection::QueryRejection>,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let lang = lang_of(parts);
        Query::<T>::from_request_parts(parts, state)
            .await
            .map(|Query(v)| ApiQuery(v))
            .map_err(|r| bad_request(lang, r))
    }
}

/// `Path<T>` 的包裝。
pub struct ApiPath<T>(pub T);

impl<T, S> FromRequestParts<S> for ApiPath<T>
where
    Path<T>: FromRequestParts<S, Rejection = axum::extract::rejection::PathRejection>,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let lang = lang_of(parts);
        Path::<T>::from_request_parts(parts, state)
            .await
            .map(|Path(v)| ApiPath(v))
            .map_err(|r| bad_request(lang, r))
    }
}

/// `Multipart` 的包裝（`Content-Type` 缺 boundary 等情形）。
pub struct ApiMultipart(pub Multipart);

impl<S> FromRequest<S> for ApiMultipart
where
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let (parts, body) = req.into_parts();
        let lang = lang_of(&parts);
        let req = Request::from_parts(parts, body);
        Multipart::from_request(req, state)
            .await
            .map(ApiMultipart)
            .map_err(|r| bad_request(lang, r))
    }
}

/// 回應用的 JSON 包裝。handler 的回應一律用它——`axum::Json` 同時是 extractor，
/// 全面禁用它（clippy.toml）才能讓裸 `Json` 的請求解析在任何寫法下都被擋下。
pub struct JsonOut<T>(pub T);

impl<T: serde::Serialize> IntoResponse for JsonOut<T> {
    fn into_response(self) -> Response {
        Json(self.0).into_response()
    }
}

#[cfg(test)]
mod tests {
    /// clippy.toml 必須列著所有原生 extractor——拿掉一筆，對應的裸用法就不再被擋。
    ///
    /// clippy 對寫法的涵蓋已逐一故障注入過（見 commit 訊息）；本測試釘的是「設定還在」。
    #[test]
    fn clippy_config_disallows_raw_extractors() {
        let text =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../clippy.toml"))
                .expect("讀 clippy.toml");
        let listed: Vec<&str> = text
            .lines()
            .filter(|l| !l.trim_start().starts_with('#'))
            .filter_map(|l| l.split("path = \"").nth(1)?.split('"').next())
            .collect();
        for want in [
            "axum::extract::Path",
            "axum::extract::Query",
            "axum::extract::Multipart",
            "axum::Json",
            "axum::extract::ConnectInfo",
        ] {
            assert!(
                listed.contains(&want),
                "clippy.toml 未禁用 {want}：{listed:?}"
            );
        }
    }

    /// rejection 原生是 **5xx**（伺服器自己的 bug）→ `Internal`，不得被壓成 400 怪到用戶端。
    ///
    /// `bad_request` 的這個分支原本沒有任何測試：刪掉它整個 server 測試仍全綠
    /// （T909 第二輪複審 tests#3，3/3 確認）。沒經 router 的 parts 抽 `Path` 會得到
    /// `MissingPathParams`——axum 原生回 500（「This is a bug in the application」）。
    #[tokio::test]
    async fn server_error_rejection_maps_to_internal_not_400() {
        use axum::extract::FromRequestParts;
        use axum::response::IntoResponse;
        for (lang, want_cjk) in [("zh-TW", true), ("en-US", false)] {
            let (mut parts, ()) = axum::http::Request::builder()
                .uri("/x")
                .header(axum::http::header::ACCEPT_LANGUAGE, lang)
                .body(())
                .unwrap()
                .into_parts();
            let Err(err) = super::ApiPath::<String>::from_request_parts(&mut parts, &()).await
            else {
                panic!("沒經 router 的 parts 應抽不出 Path");
            };
            let resp = err.into_response();
            assert_eq!(
                resp.status(),
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "{lang}"
            );
            let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(v["error"]["kind"], "internal", "{lang}");
            assert_eq!(v["error"]["i18n_key"], "server.err.internal", "{lang}");
            let msg = v["error"]["message"].as_str().unwrap();
            let cjk = msg.chars().any(|c| matches!(c as u32, 0x4E00..=0x9FFF));
            assert_eq!(cjk, want_cjk, "{lang}: message 未依語系渲染：{msg}");
        }
    }
}
