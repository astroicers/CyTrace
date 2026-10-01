//! 報表與稽核產物端點（ADR-011 §4）：線上檢視 / 下載 / ScanResult / sbom·grype。

use crate::error::{ApiError, ErrorKind, Lang};
use crate::extract::{ApiPath, ApiQuery};
use crate::state::AppState;
use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Deserialize)]
pub struct DownloadQuery {
    download: Option<u8>,
}

/// job id 僅允許 `<epoch>-<hex>` 字元集（防禦縱深：即使繞過 registry 檢查也不能路徑穿越）。
fn id_is_safe(id: &str) -> bool {
    !id.is_empty() && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// 讀 job 目錄下的產物檔（檔名固定；id 先過白名單字元集 → 無穿越風險）。
fn read_artifact(app: &AppState, id: &str, file: &str) -> Option<Vec<u8>> {
    if !id_is_safe(id) {
        return None;
    }
    let path: PathBuf = app.jobs.job_dir(id).join(file);
    std::fs::read(path).ok()
}

/// `GET /api/v1/jobs/{id}/report[?download=1]`：自包含單檔 HTML。
pub async fn report(
    State(app): State<AppState>,
    lang: Lang,
    ApiPath(id): ApiPath<String>,
    ApiQuery(q): ApiQuery<DownloadQuery>,
) -> Result<Response, ApiError> {
    if app.jobs.get(&id).is_none() {
        return Err(ApiError::new(lang, ErrorKind::NotFound));
    }
    let html = read_artifact(&app, &id, "report.html")
        .ok_or_else(|| ApiError::new(lang, ErrorKind::NotFound))?;
    let mut resp = ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], html).into_response();
    // 報表自帶 CSP（需 script-src 'unsafe-inline' 給 singlefile 內聯腳本；connect-src 'none' 零外連）。
    // 顯式設此 header → security_headers middleware 不覆蓋（見 router::security_headers）。
    resp.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        header::HeaderValue::from_static(
            "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; \
             img-src 'self' data:; font-src 'self' data:; connect-src 'none'; \
             base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
        ),
    );
    if q.download == Some(1) {
        if let Ok(v) = header::HeaderValue::from_str(&format!(
            "attachment; filename=\"cytrace-{id}.report.html\""
        )) {
            resp.headers_mut().insert(header::CONTENT_DISPOSITION, v);
        }
    }
    Ok(resp)
}

/// `GET /api/v1/jobs/{id}/result`：ScanResult JSON（ADR-009 稽核產物，可餵回 `cytrace report`）。
pub async fn result(
    State(app): State<AppState>,
    lang: Lang,
    ApiPath(id): ApiPath<String>,
) -> Result<Response, ApiError> {
    artifact_json(&app, lang, &id, "scan-result.json")
}

#[derive(Deserialize)]
pub struct ArtifactKind {
    id: String,
    kind: String,
}

/// `GET /api/v1/jobs/{id}/artifacts/{kind}`：sbom | grype | cbom（ADR-013）。
pub async fn artifact(
    State(app): State<AppState>,
    lang: Lang,
    ApiPath(p): ApiPath<ArtifactKind>,
) -> Result<Response, ApiError> {
    let file = match p.kind.as_str() {
        "sbom" => "sbom.cdx.json",
        "grype" => "grype.json",
        "cbom" => "cbom.cdx.json",
        _ => return Err(ApiError::new(lang, ErrorKind::NotFound)),
    };
    artifact_json(&app, lang, &p.id, file)
}

fn artifact_json(app: &AppState, lang: Lang, id: &str, file: &str) -> Result<Response, ApiError> {
    if app.jobs.get(id).is_none() {
        return Err(ApiError::new(lang, ErrorKind::NotFound));
    }
    let bytes =
        read_artifact(app, id, file).ok_or_else(|| ApiError::new(lang, ErrorKind::NotFound))?;
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        bytes,
    )
        .into_response())
}
