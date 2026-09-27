//! Job 執行：`Semaphore` 限併發 → `spawn_blocking` 包既有同步管線（絕不在 handler 阻塞）。
//!
//! 管線 = CLI `run_one` 的 server 版：sbom → vuln → parse → assemble → render，
//! 產物落 `jobs/<id>/`（ADR-009 稽核產物 + 報表）。

use super::{JobError, JobStatus};
use crate::state::AppState;
use cytrace_core::engine::ScanEngine;
use cytrace_core::error::CytraceError;
use cytrace_core::{failon, parse, timefmt};
use cytrace_types::{DbSnapshot, Meta, Severity, Summary};
use std::path::Path;

/// 送出 job（不清理 input）——掛載目標用。
pub fn spawn(app: AppState, job_id: String, scan_target: String, cbom: bool) {
    spawn_with_cleanup(app, job_id, scan_target, false, cbom)
}

/// 送出 job：背景 task 取票（queued）→ running → 終態。呼叫端已 persist queued 記錄。
/// `cleanup_input=true` 時，終態後刪除 `jobs/<id>/input/`（上傳型 job 縮小機密駐留窗）。
pub fn spawn_with_cleanup(
    app: AppState,
    job_id: String,
    scan_target: String,
    cleanup_input: bool,
    cbom: bool,
) {
    tokio::spawn(async move {
        let permit = match app.scan_semaphore.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => return, // semaphore closed（服務關閉中）
        };
        // 取到票才轉 running；期間可能已被取消
        if app
            .jobs
            .get(&job_id)
            .map(|r| r.status != JobStatus::Queued)
            .unwrap_or(true)
        {
            return;
        }
        app.jobs.update(&job_id, |r| {
            r.status = JobStatus::Running;
            r.started_at = Some(super::now_iso());
        });

        let engine = app.engine.clone();
        let job_dir = app.jobs.job_dir(&job_id);
        let fail_on = app.jobs.get(&job_id).and_then(|r| r.fail_on.clone());
        let result = tokio::task::spawn_blocking(move || {
            run_pipeline(
                engine.as_ref(),
                &scan_target,
                fail_on.as_deref(),
                &job_dir,
                cbom,
            )
        })
        .await;

        match result {
            Ok(Ok((summary, triggered))) => {
                app.jobs.update(&job_id, |r| {
                    r.status = JobStatus::Done;
                    r.finished_at = Some(super::now_iso());
                    r.summary = Some(summary.clone());
                    r.failon_triggered = Some(triggered);
                });
            }
            Ok(Err(e)) => {
                app.jobs.update(&job_id, |r| {
                    r.status = JobStatus::Failed;
                    r.finished_at = Some(super::now_iso());
                    r.error = Some(job_error_of(&e));
                });
            }
            Err(join_err) => {
                // spawn_blocking panic（dev/test profile 可捕捉；release panic=abort 直接 crash-only）
                app.jobs.update(&job_id, |r| {
                    r.status = JobStatus::Failed;
                    r.finished_at = Some(super::now_iso());
                    r.error = Some(JobError {
                        kind: "internal".into(),
                        i18n_key: "server.err.internal".into(),
                        detail: join_err.to_string(),
                    });
                });
            }
        }
        if cleanup_input {
            let _ = std::fs::remove_dir_all(app.jobs.job_dir(&job_id).join("input"));
        }
        drop(permit);
    });
}

fn job_error_of(e: &CytraceError) -> JobError {
    let kind = match e {
        CytraceError::Engine(_) => "engine",
        CytraceError::Parse(_) => "parse",
        CytraceError::Io(_) => "io",
        CytraceError::Config(_) => "config",
        CytraceError::DbMissing(_) => "db_missing",
        CytraceError::Cbom { .. } => "cbom",
    };
    JobError {
        kind: kind.into(),
        i18n_key: format!("server.err.{kind}"),
        detail: e.to_string(),
    }
}

/// 同步掃描管線（spawn_blocking 內執行）。回傳（summary, failon_triggered）。
fn run_pipeline(
    engine: &dyn ScanEngine,
    target: &str,
    fail_on: Option<&str>,
    job_dir: &Path,
    cbom: bool,
) -> cytrace_core::error::Result<(Summary, bool)> {
    let sbom = engine.sbom(target)?;
    let grype = engine.vuln(&sbom)?;
    std::fs::write(job_dir.join("sbom.cdx.json"), &sbom)?;
    std::fs::write(job_dir.join("grype.json"), &grype)?;

    // CBOM 失敗只影響 crypto 區段，不中止 job（ADR-013 決策 4）
    let crypto = if cbom {
        // 一次呼叫同時取得盤點結果與原始 JSON——不可為了落地而再跑一次引擎
        let (inv, raw) = cytrace_core::collect_cbom_with_raw(engine, target);
        if let Some(json) = raw {
            std::fs::write(job_dir.join("cbom.cdx.json"), &json)?;
        }
        Some(inv)
    } else {
        None
    };

    let components = parse::parse_cyclonedx(&sbom)?;
    let findings = parse::parse_grype(&grype)?;
    let meta = Meta {
        target: target.to_string(),
        tool_versions: cytrace_core::engine::tool_versions(
            crypto
                .as_ref()
                .map_or(&cytrace_types::CbomStatus::NotRequested, |c| &c.status),
        ),
        db_snapshot: DbSnapshot {
            version: "snapshot".into(),
            built: "unknown".into(),
        },
        generated_at: timefmt::epoch_to_iso(timefmt::epoch_secs()),
        scan_identity: Some(cytrace_core::engine::scan_identity()),
    };
    let result = cytrace_core::assemble_with_crypto(meta, components, findings, crypto);
    std::fs::write(
        job_dir.join("scan-result.json"),
        serde_json::to_string_pretty(&result)
            .map_err(|e| CytraceError::Parse(format!("ScanResult 序列化：{e}")))?,
    )?;

    let html = cytrace_report::render(&result)
        .map_err(|e| CytraceError::Parse(format!("報表渲染：{e}")))?;
    std::fs::write(job_dir.join("report.html"), html)?;

    let triggered = fail_on
        .map(|th| failon::triggered(&result.findings, Severity::from_grype_str(th)))
        .unwrap_or(false);
    Ok((result.summary, triggered))
}
