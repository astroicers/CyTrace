//! 包裝 axum extractor：解析失敗一律走本專案的 JSON 錯誤格式（ADR-011 §7）並依請求語系渲染。
//!
//! axum 內建的 `Json` / `Query` / `Path` / `Multipart` 解析失敗時，直接回**英文純文字**
//! （`Failed to deserialize the JSON body…`）——完全繞過 [`ApiError`]：zh-TW 用戶端收到英文、
//! console 的 client 解不出 `{"error":{…}}` 而退回泛用訊息（T909 分類 workflow 反向追蹤發現）。
//!
//! handler 一律用本模組的型別取代 axum 原生 extractor；回應的 JSON 用 [`JsonOut`]、對端位址用
//! [`PeerAddr`]。回退由兩道機械閘擋住：
//! - clippy `disallowed-types`（workspace `clippy.toml`）列 `Path`/`Query`/`Multipart`/`Json`/
//!   `ConnectInfo`。它看的是**寫出來的型別**（解析後），別名、分組 `use`、`extract::Json`、
//!   `type` 別名、標了型別的 closure 參數都繞不過。
//! - **它看不到推論出的型別**：`post(|axum::Json(b)| …)` 只以 pattern 解構、不標型別，clippy 不報
//!   （第四輪複審 server#0／claims#1）。故另以 `tests::no_closure_handlers_in_server`（syn AST）
//!   禁止以 closure 註冊 handler——具名函式的簽名一定寫出型別。
//!
//! 本模組是原生 extractor 唯一的合法使用處，`#[allow]` **逐項**標在需要的 impl 上，不用模組層級：
//! 模組層級的 allow 會連帶放行在這裡新增的 `type RawJson = axum::Json<…>` 之類的別名，其他模組
//! 再用它 clippy 就看不到（第四輪複審 server#1）。

use crate::error::{bad_request, ApiError, Lang};
#[allow(clippy::disallowed_types)] // 包裝型別的實作需要原生 extractor
use axum::extract::{ConnectInfo, FromRequest, FromRequestParts, Multipart, Path, Query, Request};
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
#[allow(clippy::disallowed_types)] // 同上；回應另由 JsonOut 包裝
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

#[allow(clippy::disallowed_types)]
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

#[allow(clippy::disallowed_types)]
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

#[allow(clippy::disallowed_types)]
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
#[allow(clippy::disallowed_types)]
pub struct ApiMultipart(pub Multipart);

#[allow(clippy::disallowed_types)]
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

/// 對端位址（登入節流用）。取代裸 `ConnectInfo`：rejection 只在 server 未以 connect_info 啟動時
/// 發生（伺服器組態 bug、非用戶端輸入），經 [`bad_request`] 轉成 JSON 500。
pub struct PeerAddr(pub std::net::SocketAddr);

#[allow(clippy::disallowed_types)]
impl<S> FromRequestParts<S> for PeerAddr
where
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let lang = lang_of(parts);
        ConnectInfo::<std::net::SocketAddr>::from_request_parts(parts, state)
            .await
            .map(|ConnectInfo(a)| PeerAddr(a))
            .map_err(|r| bad_request(lang, r))
    }
}

/// 回應用的 JSON 包裝。handler 的回應一律用它——`axum::Json` 同時是 extractor，回應改用本型別
/// 之後才能把 `Json` 列入 clippy 禁用。clippy 只看寫出來的型別；未標型別的 pattern 由
/// `tests::no_closure_handlers_in_server` 另行把關。
pub struct JsonOut<T>(pub T);

#[allow(clippy::disallowed_types)]
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

        // 生效的必須是這一份：crate 層級的 clippy.toml／.clippy.toml 會**整份取代** workspace 的
        // （不合併），禁令靜默失效而本測試照綠（第四輪複審 server#2）；CLIPPY_CONF_DIR 同理。
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let mut stack = vec![root.clone()];
        let mut extra = Vec::new();
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(&d).unwrap() {
                let p = e.unwrap().path();
                let name = p.file_name().unwrap().to_string_lossy().to_string();
                if p.is_dir() {
                    if !matches!(
                        name.as_str(),
                        "target" | "node_modules" | ".git" | "dist" | "dist-console"
                    ) {
                        stack.push(p);
                    }
                } else if (name == "clippy.toml" && d != root) || name == ".clippy.toml" {
                    // 根目錄的 .clippy.toml 也算：它優先於 clippy.toml（宣稱核對 server#1）
                    extra.push(p.display().to_string());
                } else if (name == "config" || name == "config.toml")
                    && d.file_name().is_some_and(|n| n == ".cargo")
                    && std::fs::read_to_string(&p).is_ok_and(|t| t.contains("CLIPPY_CONF_DIR"))
                {
                    // .cargo/config 的 [env] 設 CLIPPY_CONF_DIR 也會換掉生效的設定
                    extra.push(p.display().to_string());
                }
            }
        }
        // 範圍：repo 內的檔案與 Makefile／CI。repo 外的 ~/.cargo/config.toml、呼叫者的環境變數
        // 不在本測試能看到的範圍（已知限制）。
        assert!(
            extra.is_empty(),
            "有其他層級的 clippy 設定會取代 workspace 的：{extra:?}"
        );
        for f in ["Makefile", ".github/workflows/ci.yml"] {
            let t = std::fs::read_to_string(root.join(f)).unwrap();
            assert!(
                !t.contains("CLIPPY_CONF_DIR"),
                "{f} 設了 CLIPPY_CONF_DIR，會改變生效的 clippy 設定"
            );
        }
    }

    /// 以 closure 註冊 handler 一律禁止。
    ///
    /// clippy `disallowed-types` 看的是**寫出來的型別**：`post(|axum::Json(b)| async move {…})`
    /// 只以 pattern 解構、不標型別，參數型別由推論而來，clippy 看不到，裸 Json 的 rejection 照樣回
    /// 英文純文字（第四輪複審 server#0／claims#1，副本實測）。handler 一律寫成具名函式，簽名上的
    /// 型別就都在 clippy 的視野內。以 `syn` 解析 AST 判定，不受排版與註解影響。
    /// 以自由函式呼叫的路由建構子（`axum::routing::get(h)`、`any(h)`…）。
    const ROUTING_FNS: &[&str] = &[
        "get",
        "post",
        "put",
        "delete",
        "patch",
        "head",
        "options",
        "trace",
        "any",
        "on",
        "get_service",
        "post_service",
        "any_service",
        "on_service",
    ];
    /// 以方法呼叫的（`MethodRouter::post`、`Router::fallback`…）。不含 `any`：
    /// MethodRouter 沒有 `.any()`，而 `Iterator::any(|c| …)` 會誤中。
    const ROUTING_METHODS: &[&str] = &[
        "get",
        "post",
        "put",
        "delete",
        "patch",
        "head",
        "options",
        "trace",
        "on",
        "fallback",
        "method_not_allowed_fallback",
        "route_service",
        "nest_service",
        "fallback_service",
    ];

    #[derive(Default)]
    struct ClosureHandlers {
        hits: Vec<String>,
        routing_calls: usize,
        /// 本模組是原生 extractor 唯一的合法使用處（與 clippy 的逐項豁免同範圍），
        /// 包裝實作裡的 `.map(|Json(v)| ApiJson(v))` 不算。
        allow_extractor_patterns: bool,
    }

    fn is_closure(e: &syn::Expr) -> bool {
        match e {
            syn::Expr::Closure(_) => true,
            syn::Expr::Paren(p) => is_closure(&p.expr),
            syn::Expr::Group(g) => is_closure(&g.expr),
            _ => false,
        }
    }

    /// 被 clippy 禁用的原生 extractor 名稱（clippy.toml）。
    const RAW_EXTRACTORS: &[&str] = &["Json", "Path", "Query", "Multipart", "ConnectInfo"];

    fn extractor_pattern(p: &syn::Pat) -> bool {
        match p {
            syn::Pat::TupleStruct(t) => t
                .path
                .segments
                .last()
                .is_some_and(|s| RAW_EXTRACTORS.contains(&s.ident.to_string().as_str())),
            syn::Pat::Type(t) => extractor_pattern(&t.pat),
            syn::Pat::Paren(p) => extractor_pattern(&p.pat),
            _ => false,
        }
    }

    impl<'ast> syn::visit::Visit<'ast> for ClosureHandlers {
        /// 參數以原生 extractor 的 pattern 解構的 closure，不論寫在哪裡——先 `let echo = |axum::Json(b)| …`
        /// 再 `post(echo)` 就不在路由呼叫的引數位置（宣稱核對 server#0，2/2 確認）。
        fn visit_expr_closure(&mut self, c: &'ast syn::ExprClosure) {
            if !self.allow_extractor_patterns && c.inputs.iter().any(extractor_pattern) {
                self.hits
                    .push(quote::ToTokens::to_token_stream(c).to_string());
            }
            syn::visit::visit_expr_closure(self, c);
        }
        fn visit_expr_call(&mut self, c: &'ast syn::ExprCall) {
            if let syn::Expr::Path(p) = &*c.func {
                if let Some(seg) = p.path.segments.last() {
                    if ROUTING_FNS.contains(&seg.ident.to_string().as_str()) {
                        self.routing_calls += 1;
                        if c.args.iter().any(is_closure) {
                            self.hits
                                .push(quote::ToTokens::to_token_stream(c).to_string());
                        }
                    }
                }
            }
            syn::visit::visit_expr_call(self, c);
        }
        fn visit_expr_method_call(&mut self, m: &'ast syn::ExprMethodCall) {
            if ROUTING_METHODS.contains(&m.method.to_string().as_str()) {
                self.routing_calls += 1;
                if m.args.iter().any(is_closure) {
                    self.hits
                        .push(quote::ToTokens::to_token_stream(m).to_string());
                }
            }
            syn::visit::visit_expr_method_call(self, m);
        }
    }

    fn closure_handlers(src: &str, is_extract_rs: bool) -> ClosureHandlers {
        let file = syn::parse_file(src).expect("解析 Rust 原始碼");
        let mut v = ClosureHandlers {
            allow_extractor_patterns: is_extract_rs,
            ..Default::default()
        };
        syn::visit::Visit::visit_file(&mut v, &file);
        v
    }

    #[test]
    fn closure_handler_matcher_detects_known_violations() {
        let bad = [
            // 第四輪實測的兩種：不標型別的 pattern
            "fn r() -> R { Router::new().route(\"/x\", axum::routing::post(|axum::Json(b)| async move { b })) }",
            "fn r() -> R { Router::new().route(\"/p/{n}\", get(|axum::extract::Path(n)| async move { n })) }",
            "fn r() -> R { Router::new().fallback(|| async { \"x\" }) }",
            "fn r() -> R { Router::new().route(\"/y\", get(h).post(|b: String| async move { b })) }",
            "fn r() -> R { Router::new().route(\"/z\", on(MethodFilter::GET, (|| async {}))) }",
            "fn r() -> R { Router::new().route(\"/w\", axum::routing::any(|| async {})) }",
            // 先綁定再傳入：不在路由呼叫的引數位置，以 extractor pattern 抓
            "fn r() -> R { let echo = |axum::Json(b)| async move { b }; Router::new().route(\"/e\", post(echo)) }",
            "fn r() -> R { let peek = |Path(n): Path<u32>| async move { n }; Router::new().route(\"/p\", get(peek)) }",
        ];
        for s in bad {
            assert!(
                !closure_handlers(s, false).hits.is_empty(),
                "比對器漏抓：{s}"
            );
        }
        let good = [
            "fn r() -> R { Router::new().route(\"/x\", get(api::jobs::list).post(api::jobs::create)) }",
            "fn f(v: &[u8]) -> Vec<u8> { v.iter().map(|x| x + 1).collect() }",
            "fn f(s: &str) -> bool { s.chars().any(|c| c == 'x') }",
            "fn f(v: Vec<Option<u8>>) -> Vec<u8> { v.into_iter().flatten().map(|Wrapper(x)| x).collect() }",
        ];
        for s in good {
            let h = closure_handlers(s, false);
            assert!(h.hits.is_empty(), "比對器誤報：{s} → {:?}", h.hits);
        }
    }

    #[test]
    fn no_closure_handlers_in_server() {
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        let mut stack = vec![src.clone()];
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(&d).unwrap() {
                let p = e.unwrap().path();
                if p.is_dir() {
                    stack.push(p);
                } else if p.extension().is_some_and(|x| x == "rs") {
                    files.push(p);
                }
            }
        }
        let mut hits = Vec::new();
        let mut routing_calls = 0;
        for f in &files {
            let is_extract_rs = f.file_name().is_some_and(|n| n == "extract.rs");
            let v = closure_handlers(&std::fs::read_to_string(f).unwrap(), is_extract_rs);
            routing_calls += v.routing_calls;
            hits.extend(v.hits.into_iter().map(|h| format!("{}: {h}", f.display())));
        }
        // 反空轉：router.rs 至少有十來個具名 handler 的路由呼叫
        assert!(
            routing_calls >= 10,
            "只看到 {routing_calls} 個路由呼叫——解析可能失效"
        );
        assert!(
            hits.is_empty(),
            "以 closure 註冊 handler（clippy 看不到推論出的型別）：\n{}",
            hits.join("\n")
        );
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
