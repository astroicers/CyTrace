//! Jobs API（ADR-011 §4–5）：建立（掛載目標）/ 列表 / 查詢 / 取消或刪除。
//! 上傳型 job（multipart）於 T805 增補。

use crate::error::{ApiError, ErrorKind, Lang};
use crate::jobs::{runner, JobRecord, JobStatus};
use crate::state::AppState;
use crate::targets;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;

const VALID_FAIL_ON: [&str; 6] = ["critical", "high", "medium", "low", "negligible", "unknown"];

#[derive(Deserialize)]
pub struct CreateJobBody {
    target: TargetSpec,
    fail_on: Option<String>,
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
                .with_detail(format!("fail_on 不合法：{th}")));
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
) -> Result<JobRecord, ApiError> {
    let record = JobRecord::new(target_desc, fail_on)
        .map_err(|e| ApiError::new(lang, ErrorKind::Internal).with_detail(e.to_string()))?;
    app.jobs
        .insert(record.clone())
        .map_err(|e| ApiError::new(lang, ErrorKind::Io).with_detail(e.to_string()))?;
    runner::spawn(app.clone(), record.id.clone(), scan_target);
    Ok(record)
}

/// `POST /api/v1/jobs`：掛載目錄目標。
pub async fn create(
    State(app): State<AppState>,
    lang: Lang,
    Json(body): Json<CreateJobBody>,
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
    )?;
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
    Query(q): Query<ListQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let status = match q.status.as_deref() {
        None => None,
        Some(raw) => Some(
            serde_json::from_value::<JobStatus>(json!(raw)).map_err(|_| {
                ApiError::new(lang, ErrorKind::Validation)
                    .with_detail(format!("status 不合法：{raw}"))
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
    Path(id): Path<String>,
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
    Path(id): Path<String>,
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
