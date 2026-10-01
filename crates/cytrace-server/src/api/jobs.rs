//! Jobs API（ADR-011 §4–5）：建立（掛載目標）/ 列表 / 查詢 / 取消或刪除。
//! 上傳型 job（multipart）於 T805 增補。

use crate::error::{ApiError, ErrorKind, Lang};
use crate::extract::{ApiJson, ApiMultipart, ApiPath, ApiQuery};
use crate::jobs::{runner, JobRecord, JobStatus};
use crate::state::AppState;
use crate::{targets, upload};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;
use std::io::Write;

const VALID_FAIL_ON: [&str; 6] = ["critical", "high", "medium", "low", "negligible", "unknown"];

#[derive(Deserialize)]
pub struct CreateJobBody {
    target: TargetSpec,
    fail_on: Option<String>,
    /// 併同盤點密碼學資產（CBOM；ADR-013）。預設關閉。
    #[serde(default)]
    cbom: bool,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TargetSpec {
    Mounted { root: String, path: String },
}

/// 共同前置檢查：DB 就位、fail_on 合法、佇列未滿。
pub(crate) fn precheck(app: &AppState, lang: Lang, fail_on: Option<&str>) -> Result<(), ApiError> {
    if !app.cfg.db_present() {
        return Err(ApiError::new(lang, ErrorKind::DbMissing));
    }
    if let Some(th) = fail_on {
        if !VALID_FAIL_ON.contains(&th) {
            return Err(ApiError::new(lang, ErrorKind::Validation)
                // 可用值由 VALID_FAIL_ON 插值，不在文案裡手抄一份（改一邊忘一邊的反模式）
                .with_message(
                    "server.err.invalid_fail_on",
                    &[("value", th), ("allowed", &VALID_FAIL_ON.join(" / "))],
                )
                .with_detail(th));
        }
    }
    if app.jobs.active_count() >= app.cfg.max_queued {
        return Err(ApiError::new(lang, ErrorKind::QueueFull));
    }
    Ok(())
}

/// 建立 job 記錄並送入 runner（掛載與上傳路徑共用）。
pub(crate) fn submit(
    app: &AppState,
    lang: Lang,
    target_desc: String,
    scan_target: String,
    fail_on: Option<String>,
    cbom: bool,
) -> Result<JobRecord, ApiError> {
    let record = JobRecord::new(target_desc, fail_on)
        .map_err(|e| ApiError::new(lang, ErrorKind::Internal).with_detail(e.to_string()))?;
    app.jobs
        .insert(record.clone())
        .map_err(|e| ApiError::new(lang, ErrorKind::Io).with_detail(e.to_string()))?;
    runner::spawn(app.clone(), record.id.clone(), scan_target, cbom);
    Ok(record)
}

/// `POST /api/v1/jobs`：掛載目錄目標。
pub async fn create(
    State(app): State<AppState>,
    lang: Lang,
    ApiJson(body): ApiJson<CreateJobBody>,
) -> Result<Response, ApiError> {
    precheck(&app, lang, body.fail_on.as_deref())?;
    let TargetSpec::Mounted { root, path } = &body.target;
    let resolved = targets::resolve(&app.cfg.scan_roots, root, path).map_err(|e| {
        // 對外一律 403，不洩漏檔案系統結構；原始輸入進 detail（稽核）
        ApiError::new(lang, ErrorKind::ForbiddenPath)
            .with_detail(format!("{}: root={root} path={path}", e.as_str()))
    })?;
    let record = submit(
        &app,
        lang,
        format!("mounted:{root}/{path}"),
        format!("dir:{}", resolved.display()),
        body.fail_on.clone(),
        body.cbom,
    )?;
    Ok((StatusCode::ACCEPTED, Json(record)).into_response())
}

/// `POST /api/v1/jobs/upload`：multipart 一步式（file + fail_on?）。串流落盤→安全解壓→建 job。
///
/// 每個請求先建**唯一 job 目錄**（unique id），直接串流進該 job 的 `input/original/`——
/// 不共用 staging，避免併發上傳交叉污染（安全審查 B1）。失敗時整個 job 目錄移除。
pub async fn upload(
    State(app): State<AppState>,
    lang: Lang,
    ApiMultipart(mut multipart): ApiMultipart,
) -> Result<Response, ApiError> {
    // 先建唯一 job 記錄與目錄（尚不 insert registry；失敗即刪目錄，不留 queued job）。
    let mut record = JobRecord::new("upload:".into(), None)
        .map_err(|e| ApiError::new(lang, ErrorKind::Internal).with_detail(e.to_string()))?;
    let job_dir = app.jobs.job_dir(&record.id);
    let input_dir = job_dir.join("input");
    std::fs::create_dir_all(input_dir.join("original"))
        .map_err(|e| ApiError::new(lang, ErrorKind::Io).with_detail(e.to_string()))?;

    // 失敗時清整個 job 目錄的 helper。
    let cleanup = |dir: &std::path::Path| {
        let _ = std::fs::remove_dir_all(dir);
    };

    let mut saved: Option<(std::path::PathBuf, String)> = None;
    let mut fail_on: Option<String> = None;
    // 上傳路徑的 CBOM 開關（multipart 欄位 `cbom=true`；ADR-013，預設關閉）
    let mut cbom = false;
    let limit = app.cfg.max_upload_bytes;

    loop {
        let field_res = multipart.next_field().await;
        let Some(mut field) = (match field_res {
            Ok(f) => f,
            Err(e) => {
                cleanup(&job_dir);
                return Err(ApiError::new(lang, ErrorKind::Validation).with_detail(e.to_string()));
            }
        }) else {
            break;
        };
        match field.name() {
            Some("file") => {
                let fname = field.file_name().unwrap_or("upload").to_string();
                let dest = upload::original_path(&input_dir, &fname);
                let mut out = match std::fs::File::create(&dest) {
                    Ok(f) => f,
                    Err(e) => {
                        cleanup(&job_dir);
                        return Err(ApiError::new(lang, ErrorKind::Io).with_detail(e.to_string()));
                    }
                };
                let mut written: u64 = 0;
                loop {
                    match field.chunk().await {
                        Ok(Some(chunk)) => {
                            written += chunk.len() as u64;
                            if written > limit {
                                cleanup(&job_dir);
                                return Err(ApiError::new(lang, ErrorKind::PayloadTooLarge)
                                    .with_message(
                                        "server.err.upload_too_large",
                                        &[("limit", &limit.to_string())],
                                    )
                                    .with_detail(limit.to_string()));
                            }
                            if let Err(e) = out.write_all(&chunk) {
                                cleanup(&job_dir);
                                return Err(
                                    ApiError::new(lang, ErrorKind::Io).with_detail(e.to_string())
                                );
                            }
                        }
                        Ok(None) => break,
                        Err(e) => {
                            cleanup(&job_dir);
                            return Err(ApiError::new(lang, ErrorKind::Validation)
                                .with_detail(e.to_string()));
                        }
                    }
                }
                saved = Some((dest, upload::sanitize_filename(&fname)));
            }
            Some("cbom") => {
                cbom = field
                    .text()
                    .await
                    .map(|v| matches!(v.trim(), "1" | "true" | "on"))
                    .unwrap_or(false);
            }
            Some("fail_on") => {
                fail_on = field
                    .text()
                    .await
                    .ok()
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty());
            }
            _ => {} // 忽略未知欄位
        }
    }

    let Some((saved_path, original_name)) = saved else {
        cleanup(&job_dir);
        return Err(ApiError::new(lang, ErrorKind::Validation)
            .with_message("server.err.missing_file_field", &[]));
    };

    // 欄位齊全 → precheck（DB/fail_on/佇列）
    if let Err(e) = precheck(&app, lang, fail_on.as_deref()) {
        cleanup(&job_dir);
        return Err(e);
    }

    // 安全解壓（spawn_blocking：解壓可能吃 CPU/IO）；產物落此 job 的 input/extracted/。
    let input_c = input_dir.clone();
    let saved_c = saved_path.clone();
    let name_c = original_name.clone();
    let max_extract = app.cfg.max_extract_bytes;
    let prep = tokio::task::spawn_blocking(move || {
        upload::prepare(&saved_c, &name_c, &input_c, max_extract)
    })
    .await;

    let prep = match prep {
        Ok(Ok(p)) => p,
        Ok(Err(ae)) => {
            cleanup(&job_dir);
            let kind = match ae.kind() {
                "forbidden_path" => ErrorKind::ForbiddenPath,
                "extract_too_large" => ErrorKind::PayloadTooLarge,
                _ => ErrorKind::UnsupportedArchive,
            };
            // 用 ArchiveError 自己的精確鍵（此前在生產碼無呼叫者，全被壓成粗粒度 kind 的泛用訊息）
            return Err(ApiError::new(lang, kind)
                .with_message(ae.i18n_key(), &[])
                .with_detail(ae.detail().to_string()));
        }
        Err(e) => {
            cleanup(&job_dir);
            return Err(ApiError::new(lang, ErrorKind::Internal).with_detail(e.to_string()));
        }
    };

    // 補齊 record（target 描述 + fail_on）並 insert registry。
    record.target = format!("upload:{original_name}");
    record.fail_on = fail_on;
    app.jobs
        .insert(record.clone())
        .map_err(|e| ApiError::new(lang, ErrorKind::Io).with_detail(e.to_string()))?;
    runner::spawn_with_cleanup(
        app.clone(),
        record.id.clone(),
        prep.scan_target,
        !app.cfg.keep_input,
        cbom,
    );
    Ok((StatusCode::ACCEPTED, Json(record)).into_response())
}

#[derive(Deserialize)]
pub struct ListQuery {
    status: Option<String>,
    limit: Option<usize>,
    offset: Option<usize>,
}

/// `GET /api/v1/jobs`：時間倒序列表。
pub async fn list(
    State(app): State<AppState>,
    lang: Lang,
    ApiQuery(q): ApiQuery<ListQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let status = match q.status.as_deref() {
        None => None,
        Some(raw) => Some(
            serde_json::from_value::<JobStatus>(json!(raw)).map_err(|_| {
                ApiError::new(lang, ErrorKind::Validation)
                    .with_message("server.err.invalid_status", &[("value", raw)])
                    .with_detail(raw)
            })?,
        ),
    };
    let (jobs, total) = app.jobs.list(
        status,
        q.limit.unwrap_or(50).min(200),
        q.offset.unwrap_or(0),
    );
    Ok(Json(json!({ "jobs": jobs, "total": total })))
}

/// `GET /api/v1/jobs/{id}`。
pub async fn get(
    State(app): State<AppState>,
    lang: Lang,
    ApiPath(id): ApiPath<String>,
) -> Result<Json<JobRecord>, ApiError> {
    app.jobs
        .get(&id)
        .map(Json)
        .ok_or_else(|| ApiError::new(lang, ErrorKind::NotFound))
}

/// `DELETE /api/v1/jobs/{id}`：queued → 取消；終態 → 刪除；running → 409。
pub async fn delete(
    State(app): State<AppState>,
    lang: Lang,
    ApiPath(id): ApiPath<String>,
) -> Result<StatusCode, ApiError> {
    let record = app
        .jobs
        .get(&id)
        .ok_or_else(|| ApiError::new(lang, ErrorKind::NotFound))?;
    match record.status {
        JobStatus::Queued => {
            app.jobs.cancel_if_queued(&id);
            Ok(StatusCode::NO_CONTENT)
        }
        JobStatus::Running => Err(ApiError::new(lang, ErrorKind::Conflict)),
        _ => {
            app.jobs
                .remove(&id)
                .map_err(|e| ApiError::new(lang, ErrorKind::Io).with_detail(e.to_string()))?;
            Ok(StatusCode::NO_CONTENT)
        }
    }
}

/// `GET /api/v1/targets`：白名單根清單（只給名稱，不洩路徑）。
pub async fn targets_list(State(app): State<AppState>) -> Json<serde_json::Value> {
    let roots: Vec<serde_json::Value> = app
        .cfg
        .scan_roots
        .iter()
        .map(|(name, _)| json!({ "name": name }))
        .collect();
    Json(json!({ "roots": roots }))
}
