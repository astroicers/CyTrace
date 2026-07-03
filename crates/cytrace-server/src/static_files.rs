//! Console 靜態資產服務（rust-embed，ADR-011）。
//!
//! console SPA 產物（`frontend/dist-console/`）於 build 期複製到 `assets/console/` 並內嵌。
//! hash routing：所有非 asset、非 API 路徑都回 `console.html`（SPA fallback，無需後端路由表）。

use axum::http::{header, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "assets/console/"]
struct ConsoleAssets;

fn serve_embedded(path: &str) -> Option<Response> {
    let file = ConsoleAssets::get(path)?;
    let mime = mime_guess::from_path(path).first_or_octet_stream();
    Some(
        (
            [(header::CONTENT_TYPE, mime.as_ref())],
            file.data.into_owned(),
        )
            .into_response(),
    )
}

/// SPA handler：asset 命中回該檔；否則回 console.html（hash routing 全靠前端）。
/// 找不到 index（未 build console）→ 503 純文字提示。
pub async fn console_spa(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    if !path.is_empty() {
        if let Some(resp) = serve_embedded(path) {
            return resp;
        }
    }
    match serve_embedded("console.html") {
        Some(resp) => resp,
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            "console not built (run `make frontend-console`)",
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn console_html_is_embedded() {
        // 佔位檔或真實產物皆可；確認 embed 資料夾存在且非空。
        assert!(
            ConsoleAssets::get("console.html").is_some(),
            "assets/console/console.html 應存在（make frontend-console 或佔位）"
        );
    }
}
