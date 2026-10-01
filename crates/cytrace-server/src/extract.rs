//! 包裝 axum extractor：解析失敗一律走本專案的 JSON 錯誤格式（ADR-011 §7）並依請求語系渲染。
//!
//! axum 內建的 `Json` / `Query` / `Path` / `Multipart` 解析失敗時，直接回**英文純文字**
//! （`Failed to deserialize the JSON body…`）——完全繞過 [`ApiError`]：zh-TW 用戶端收到英文、
//! console 的 client 解不出 `{"error":{…}}` 而退回泛用訊息（T909 分類 workflow 反向追蹤發現）。
//!
//! handler 一律用本模組的型別取代 axum 原生 extractor；`tests::no_bare_axum_extractors_in_handlers`
//! 機械地擋住回退——分析找到 6 處、人工清點出 10 處，靠窮舉是會漏的。

use crate::error::{bad_request, ApiError, Lang};
use axum::extract::{FromRequest, FromRequestParts, Multipart, Path, Query, Request};
use axum::http::request::Parts;
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

#[cfg(test)]
mod tests {
    /// handler 參數不得出現裸 axum extractor——否則解析失敗會繞過 JSON 錯誤格式回英文純文字。
    ///
    /// 掃 `src/api/*.rs`。反空轉：必須同時看到足量的包裝型別使用（≥ 10，當前實值），
    /// 否則表示掃描本身失效（路徑錯、檔案搬家），「沒有裸 extractor」這個結論不含資訊。
    #[test]
    fn no_bare_axum_extractors_in_handlers() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/src/api");
        let mut bare = Vec::new();
        let mut wrapped = 0usize;
        for entry in std::fs::read_dir(dir).expect("讀 src/api") {
            let path = entry.unwrap().path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let src = std::fs::read_to_string(&path).unwrap();
            for (i, line) in src.lines().enumerate() {
                let t = line.trim_start();
                if t.starts_with("//") {
                    continue;
                }
                // handler 參數形如 `Json(body): Json<T>,` / `mut multipart: Multipart,`
                let is_param = t.ends_with(',') || t.ends_with(')');
                if !is_param {
                    continue;
                }
                for bare_ty in [": Json<", ": Query<", ": Path<", ": Multipart,"] {
                    if t.contains(bare_ty) {
                        bare.push(format!("{}:{}  {}", path.display(), i + 1, t));
                    }
                }
                for w in [": ApiJson<", ": ApiQuery<", ": ApiPath<", ": ApiMultipart"] {
                    if t.contains(w) {
                        wrapped += 1;
                    }
                }
            }
        }
        assert!(
            bare.is_empty(),
            "handler 參數出現裸 axum extractor——解析失敗會繞過 ApiError 回英文純文字：\n{}",
            bare.join("\n")
        );
        assert!(
            wrapped >= 10,
            "只看到 {wrapped} 處包裝型別使用（預期 ≥ 10）——掃描可能已失效，此時「沒有裸 extractor」不含資訊"
        );
    }
}
