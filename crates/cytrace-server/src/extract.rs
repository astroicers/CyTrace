//! 包裝 axum extractor：解析失敗一律走本專案的 JSON 錯誤格式（ADR-011 §7）並依請求語系渲染。
//!
//! axum 內建的 `Json` / `Query` / `Path` / `Multipart` 解析失敗時，直接回**英文純文字**
//! （`Failed to deserialize the JSON body…`）——完全繞過 [`ApiError`]：zh-TW 用戶端收到英文、
//! console 的 client 解不出 `{"error":{…}}` 而退回泛用訊息（T909 分類 workflow 反向追蹤發現）。
//!
//! handler 一律用本模組的型別取代 axum 原生 extractor。回退由兩道機械閘擋住：
//! `Path`/`Query`/`Multipart` 由 clippy `disallowed-types`（workspace `clippy.toml`）；
//! `Json` 由本模組的簽名級文字閘（見 `tests`）。分析找到 6 處、人工清點出 10 處——
//! 靠窮舉是會漏的。例外：`ConnectInfo`（見 `tests::ALLOWED_BARE` 的理由）。

// 本模組是 axum 原生 extractor 唯一的合法使用處（clippy.toml disallowed-types）
#![allow(clippy::disallowed_types)]

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
    //! `Path`/`Query`/`Multipart` 由 clippy `disallowed-types` 擋（看解析後的型別，
    //! 排版、別名、全限定路徑、所在檔案都繞不過）。`Json` 同時是回應型別無法用 clippy 禁，
    //! 由本模組的**簽名級**文字閘把關。
    //!
    //! 初版逐行比對、只看行尾為 `,`/`)` 的行、只掃 `src/api/` 一層——rustfmt 收成單行的
    //! 簽名、`axum::Json<T>` 全限定寫法、`as` 別名、router.rs 裡的 handler 全都漏過；
    //! 反空轉 `wrapped >= 10` 只證明「讀到了檔」，沒證明「抓得到違規」
    //! （T909 對抗式複審 major，3/3 確認）。本版：
    //! 1. 以 `fn` 簽名為單位解析參數（括號配對、頂層逗號切分），與排版無關；
    //! 2. 型別比對涵蓋 `Json<` / `axum::Json<` / `axum::extract::Json<` 與 `use … Json as X` 別名；
    //! 3. 掃整個 `src/`（遞迴）；
    //! 4. **正向對照**：先對內嵌的已知違規樣本跑比對器，斷言全數抓到——
    //!    反空轉驗的是偵測能力，不是讀檔。

    /// `ConnectInfo` 的 rejection 只在 server 未以 `into_make_service_with_connect_info`
    /// 啟動時發生（正式 `serve()` 必定有），屬伺服器組態 bug 而非用戶端輸入。
    /// 刻意不包裝，於此明列；新增例外必須附理由。
    const ALLOWED_BARE: &[(&str, &str)] = &[("api/session.rs", "ConnectInfo")];

    /// 取出 `fn` 簽名的參數清單（頂層逗號切分後的各參數原文）。
    fn fn_params(src: &str) -> Vec<String> {
        let b = src.as_bytes();
        let mut out = Vec::new();
        let mut i = 0;
        while let Some(off) = src[i..].find("fn ") {
            let at = i + off;
            // `fn` 必須是獨立詞（排除 `async_fn ` 之類）
            let word_start = at == 0 || !(b[at - 1].is_ascii_alphanumeric() || b[at - 1] == b'_');
            i = at + 3;
            if !word_start {
                continue;
            }
            let Some(open_rel) = src[i..].find('(') else {
                break;
            };
            // 名稱與 `(` 之間只允許識別字、空白與泛型參數
            if src[i..i + open_rel].contains(['{', ';', '=']) {
                continue;
            }
            let open = i + open_rel;
            let (mut depth, mut j, mut cur, mut angle) = (0i32, open, String::new(), 0i32);
            while j < b.len() {
                let c = b[j] as char;
                match c {
                    '(' => {
                        depth += 1;
                        if depth > 1 {
                            cur.push(c);
                        }
                    }
                    ')' => {
                        depth -= 1;
                        if depth == 0 {
                            if !cur.trim().is_empty() {
                                out.push(cur.trim().to_string());
                            }
                            break;
                        }
                        cur.push(c);
                    }
                    '<' => {
                        angle += 1;
                        cur.push(c);
                    }
                    '>' => {
                        // `->` 不算泛型關閉
                        if j > 0 && b[j - 1] != b'-' {
                            angle -= 1;
                        }
                        cur.push(c);
                    }
                    ',' if depth == 1 && angle == 0 => {
                        out.push(cur.trim().to_string());
                        cur.clear();
                    }
                    _ => {
                        if depth >= 1 {
                            cur.push(c);
                        }
                    }
                }
                j += 1;
            }
            i = j.max(i);
        }
        out
    }

    /// 參數的型別部分（pattern 與型別之間那個單獨的 `:`；跳過 `::`）。
    fn param_type(param: &str) -> Option<&str> {
        let b = param.as_bytes();
        let mut k = 0;
        while k < b.len() {
            if b[k] == b':' {
                let dbl = (k + 1 < b.len() && b[k + 1] == b':') || (k > 0 && b[k - 1] == b':');
                if !dbl {
                    return Some(param[k + 1..].trim());
                }
                k += 2;
                continue;
            }
            k += 1;
        }
        None
    }

    /// 回報檔案內所有以裸 axum `Json`（含全限定與別名）或清單外裸 `ConnectInfo` 作為參數的位置。
    fn bare_extractors(src: &str) -> Vec<String> {
        // `use axum::Json as X;` / `use axum::extract::Json as X;` 的別名
        let mut json_names: Vec<String> = vec![
            "Json".into(),
            "axum::Json".into(),
            "axum::extract::Json".into(),
        ];
        for line in src.lines() {
            let t = line.trim();
            for pre in ["use axum::Json as ", "use axum::extract::Json as "] {
                if let Some(rest) = t.strip_prefix(pre) {
                    json_names.push(rest.trim_end_matches(';').trim().to_string());
                }
            }
        }
        let mut hits = Vec::new();
        for p in fn_params(src) {
            let Some(ty) = param_type(&p) else { continue };
            let ty: String = ty.split_whitespace().collect();
            if json_names.iter().any(|n| ty.starts_with(&format!("{n}<"))) {
                hits.push(p.clone());
            }
            if ty.starts_with("ConnectInfo<") || ty.starts_with("axum::extract::ConnectInfo<") {
                hits.push(p.clone());
            }
        }
        hits
    }

    /// 正向對照：比對器必須抓得到已知違規的各種寫法，且不得誤報合法寫法。
    #[test]
    fn matcher_detects_known_violations() {
        let bad = [
            // rustfmt 收成單行的簽名（行尾是 `{`）
            "pub async fn a(State(s): State<S>, Json(b): Json<T>) -> Response {",
            // 全限定路徑
            "pub async fn b(\n    axum::Json(b): axum::Json<T>,\n) -> R {",
            "pub async fn c(body: axum::extract::Json<T>) -> R {",
            // 別名
            "use axum::Json as J;\npub async fn d(J(b): J<T>) -> R {",
            // 裸 ConnectInfo
            "pub async fn e(ConnectInfo(p): ConnectInfo<SocketAddr>) -> R {",
        ];
        for s in bad {
            assert!(!bare_extractors(s).is_empty(), "比對器漏抓已知違規：\n{s}");
        }
        let good = [
            "pub async fn f(ApiJson(b): ApiJson<T>) -> Json<serde_json::Value> {",
            "fn g() -> Json<T> { Json(t) }",
            "pub async fn h(lang: Lang, ApiPath(id): ApiPath<String>) -> Result<Json<R>, ApiError> {",
        ];
        for s in good {
            assert!(
                bare_extractors(s).is_empty(),
                "比對器誤報合法寫法：\n{s}\n→ {:?}",
                bare_extractors(s)
            );
        }
    }

    fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for e in std::fs::read_dir(dir).expect("讀 src") {
            let p = e.unwrap().path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.extension().and_then(|x| x.to_str()) == Some("rs") {
                out.push(p);
            }
        }
    }

    /// handler 參數不得出現裸 `Json`（`Path`/`Query`/`Multipart` 由 clippy 擋）。
    #[test]
    fn no_bare_axum_extractors_in_handlers() {
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        walk(&src, &mut files);
        assert!(
            files.len() >= 15,
            "只找到 {} 個 .rs——掃描範圍可能失效",
            files.len()
        );

        let mut bare = Vec::new();
        let mut wrapped = 0usize;
        for f in &files {
            let rel = f
                .strip_prefix(&src)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            if rel == "extract.rs" {
                continue; // 包裝型別本身
            }
            let text = std::fs::read_to_string(f).unwrap();
            for p in fn_params(&text) {
                if let Some(ty) = param_type(&p) {
                    if ["ApiJson<", "ApiQuery<", "ApiPath<", "ApiMultipart"]
                        .iter()
                        .any(|w| ty.starts_with(w))
                    {
                        wrapped += 1;
                    }
                }
            }
            for hit in bare_extractors(&text) {
                let allowed = ALLOWED_BARE
                    .iter()
                    .any(|(af, what)| *af == rel && hit.contains(what));
                if !allowed {
                    bare.push(format!("{rel}: {hit}"));
                }
            }
        }
        assert!(
            bare.is_empty(),
            "handler 參數出現裸 axum extractor——解析失敗會繞過 ApiError 回英文純文字：\n{}",
            bare.join("\n")
        );
        // 補充性的反空轉（主要的偵測能力證明在 matcher_detects_known_violations）
        assert!(
            wrapped >= 10,
            "只解析到 {wrapped} 處包裝型別參數（預期 ≥ 10）——簽名解析可能失效"
        );
    }
}
