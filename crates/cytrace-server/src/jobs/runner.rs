//! Job 執行：`Semaphore` 限併發 → `spawn_blocking` 包既有同步管線（絕不在 handler 阻塞）。
//!
//! 管線 = CLI `run_one` 的 server 版：sbom → vuln → parse → assemble → render，
//! 產物落 `jobs/<id>/`（ADR-009 稽核產物 + 報表）。

use super::{JobError, JobStatus};
use crate::error::Lang;
use crate::state::AppState;
use cytrace_core::engine::ScanEngine;
use cytrace_core::error::CytraceError;
use cytrace_core::{failon, parse, timefmt};
use cytrace_types::{Meta, Severity, Summary};
use std::path::Path;

/// 送出 job（不清理 input）——掛載目標用。
///
/// `lang` 是送出掃描那次請求的語系：報表 HTML 是靜態產物，以它決定開啟時的語言（T918）。
pub fn spawn(app: AppState, job_id: String, scan_target: String, cbom: bool, lang: Lang) {
    spawn_with_cleanup(app, job_id, scan_target, false, cbom, lang)
}

/// 送出 job：背景 task 取票（queued）→ running → 終態。呼叫端已 persist queued 記錄。
/// `cleanup_input=true` 時，終態後刪除 `jobs/<id>/input/`（上傳型 job 縮小機密駐留窗）。
pub fn spawn_with_cleanup(
    app: AppState,
    job_id: String,
    scan_target: String,
    cleanup_input: bool,
    cbom: bool,
    lang: Lang,
) {
    tokio::spawn(async move {
        let permit = match app.scan_semaphore.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => return, // semaphore closed（服務關閉中）
        };
        // 取到票才轉 running；期間可能已被取消。檢查與轉移須在同一把鎖內完成，
        // 否則取消可能落在兩者之間：input/ 已被刪，這裡卻照樣開始掃描（#39 複審）
        if !app.jobs.start_if_queued(&job_id) {
            return;
        }

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
                lang,
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
            app.jobs.remove_input(&job_id);
        }
        drop(permit);
    });
}

/// `CytraceError` → 持久化的 `JobError`。
///
/// **這是 server 掃描失敗的正常路徑**（`Ok(Err(e))` 分支），不是 `ApiError::from_core`
/// ——後者目前無生產呼叫者。第七輪把「detail 不得夾帶中文散文」修在有測試的
/// `from_core`，卻沒修在真正在跑的這裡（第八輪複審 finding B）。
///
/// 兩個欄位的分工：
/// - `i18n_key`：**可翻譯**的鍵，由查詢時的請求語系渲染（job 是非同步的，此處沒有語系）——
///   server 端由 `api::jobs::job_view` 在 get / list 回應時附上 `error.message`，console 另以
///   `describeJobError` 渲染。
///   `Cbom` 變體直接用它自己的 `cbom.err.*` 鍵——那才是成因；
///   套 `server.err.cbom` 會把「逾時」與「目標被拒」壓成同一句話，
///   而 catalog 裡也根本沒有 `server.err.cbom` 這個鍵（前端會顯示裸鍵）。
/// - `detail`：**不可翻譯**的部分（路徑、秒數、子程序訊息）。走
///   [`CytraceError::untranslatable_detail`] 單一出口，不用 `to_string()`
///   ——後者會帶上本型別的分類前綴（T912 前為中文），且 `Cbom` 的 `Display` 是「鍵: 細節」，
///   等於把裸鍵送出 API。
fn job_error_of(e: &CytraceError) -> JobError {
    // 分類與鍵的對應住在 core（CLI 終端訊息用同一份；T912）
    JobError {
        kind: e.kind().into(),
        i18n_key: e.i18n_key().into(),
        detail: e.untranslatable_detail().unwrap_or_default(),
    }
}

/// 同步掃描管線（spawn_blocking 內執行）。回傳（summary, failon_triggered）。
fn run_pipeline(
    engine: &dyn ScanEngine,
    target: &str,
    fail_on: Option<&str>,
    job_dir: &Path,
    cbom: bool,
    lang: Lang,
) -> cytrace_core::error::Result<(Summary, bool)> {
    // SPDX（備；FR-001）與 CycloneDX 出自同一次 syft 執行，web 模式一律附上（T919）——
    // 下載哪一種由使用者在 console 選，不必在送出時先決定
    let (sbom, spdx) = engine.sbom_with_spdx(target)?;
    let grype = engine.vuln(&sbom)?;
    std::fs::write(job_dir.join("sbom.cdx.json"), &sbom)?;
    if let Some(s) = &spdx {
        std::fs::write(job_dir.join("sbom.spdx.json"), s)?;
    }
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
    // 弱點對應元件位置要用同一次掃描的元件清單（ADR-009「修訂：schema v3」）
    let findings = parse::parse_grype_for(&grype, &components)?;
    let meta = Meta {
        target: target.to_string(),
        tool_versions: cytrace_core::engine::tool_versions(
            crypto
                .as_ref()
                .map_or(&cytrace_types::CbomStatus::NotRequested, |c| &c.status),
        ),
        // 真值取自 grype db status；失敗回 "unavailable" sentinel（見 engine::db_snapshot）
        db_snapshot: cytrace_core::engine::db_snapshot(),
        generated_at: timefmt::epoch_to_iso(timefmt::epoch_secs()),
        scan_identity: Some(cytrace_core::engine::scan_identity()),
    };
    let result = cytrace_core::assemble_with_crypto(meta, components, findings, crypto);
    std::fs::write(
        job_dir.join("scan-result.json"),
        serde_json::to_string_pretty(&result)
            .map_err(|e| CytraceError::Parse(format!("scan-result serialize: {e}")))?,
    )?;

    // `{e}` 會帶出 CytraceError 的 Display——每個變體都有分類前綴（T912 前為中文「設定錯誤：…」），
    // 只換外層前綴等於沒修（T909 完整性批判抓到的漏網）。取不翻譯的內文。
    // 這是**防禦性**修改：樣板以 include_str! 內嵌且 CI 驗過含 sentinel、ScanResult 序列化不會
    // 失敗，此分支目前從任何輸入都進不來，也沒有測試能讓它轉紅（第二輪完整性批判更正
    // e5e1f21 把它列為「實測可重現」的說法）。
    let html = cytrace_report::render(&result, lang.code()).map_err(|e| {
        CytraceError::Parse(format!(
            "report render: {}",
            e.untranslatable_detail().unwrap_or_default()
        ))
    })?;
    std::fs::write(job_dir.join("report.html"), html)?;

    let triggered = fail_on
        .map(|th| failon::triggered(&result.findings, Severity::from_grype_str(th)))
        .unwrap_or(false);
    Ok((result.summary, triggered))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `JobError.detail` 不得夾帶本型別的中文散文，`i18n_key` 不得是查不到的鍵。
    ///
    /// 這條不變量第七輪被修在 `ApiError::from_core`（無生產呼叫者），而**真正在跑的是
    /// 本檔的 `job_error_of`**，它當時仍用 `e.to_string()`（第八輪複審 finding B）。
    /// server 側對此原本零覆蓋，故修在沒測試的地方就沒被修到。
    #[test]
    fn job_error_detail_never_carries_prose_or_bare_keys() {
        use cytrace_i18n::Catalog;

        let cases: Vec<(&str, CytraceError)> = vec![
            ("Engine", CytraceError::Engine("exit 2: boom".into())),
            ("Parse", CytraceError::Parse("expected value".into())),
            ("Config", CytraceError::Config("missing flag".into())),
            (
                "DbMissing",
                CytraceError::DbMissing("/var/lib/grype/db".into()),
            ),
            (
                "Io",
                CytraceError::Io(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "permission denied",
                )),
            ),
            (
                "Cbom",
                CytraceError::Cbom {
                    key: "cbom.err.timeout",
                    detail: Some("600".into()),
                },
            ),
            // detail 可為空的**可達**輸入：少了它，下面那條「detail 可空但 i18n_key
            // 必須自帶成因」的斷言在本測試裡一次都沒有輸入可驗（第十輪複審）
            (
                "Cbom-no-detail",
                CytraceError::Cbom {
                    key: "cbom.err.empty_output",
                    detail: None,
                },
            ),
        ];

        for (name, err) in cases {
            let je = job_error_of(&err);

            // detail 只放不可翻譯內容
            let offending: Vec<char> = je
                .detail
                .chars()
                .filter(
                    |c| matches!(*c as u32, 0x4E00..=0x9FFF | 0x3000..=0x303F | 0xFF00..=0xFFEF),
                )
                .collect();
            assert!(
                offending.is_empty(),
                "{name}: JobError.detail 夾帶中文散文 {offending:?}：{}\n\
                 （後果：console 與 API 在 en-US 下顯示中文）",
                je.detail
            );
            assert!(
                !je.detail.starts_with("cbom.err."),
                "{name}: detail 不得是裸 i18n 鍵：{}",
                je.detail
            );
            // detail 為空是合法的（`empty_output` 本就沒有可帶出的細節）；
            // 此時成因必須完全由 i18n_key 承擔，下面那條斷言即為此。
            // 刻意不斷言 detail 非空：`Cbom { key: "cbom.err.empty_output", detail: None }`
            // 是可達狀態，經 `unwrap_or_default()` 就是空字串（同檔下一支測試正是斷言它為 ""）。
            // 原本這裡寫 `assert!(!je.detail.is_empty())`，對所選輸入恆真、且與那條規範
            // 互相矛盾（第九輪複審）。detail 可空，**但此時 i18n_key 必須自帶成因**：
            assert!(
                !je.i18n_key.is_empty(),
                "{name}: detail 可為空，但 i18n_key 必須自帶成因，否則前端無話可說"
            );

            // i18n_key 必須在兩語系都查得到（t() 回傳鍵本身即代表查不到）
            for lang in ["zh-TW", "en-US"] {
                let cat = Catalog::load(lang);
                assert_ne!(
                    cat.t(&je.i18n_key, &[]),
                    je.i18n_key,
                    "{name}: {lang} 查不到 i18n_key {}——前端會顯示裸鍵\n\
                     （`server.err.cbom` 這個鍵在 catalog 裡從來沒存在過）",
                    je.i18n_key
                );
            }
        }
    }

    /// CBOM 失敗的 `i18n_key` 必須是**成因鍵**，而非壓平成單一 kind 鍵。
    #[test]
    fn cbom_job_error_keeps_the_specific_cause_key() {
        for (key, detail) in [
            ("cbom.err.timeout", Some("600".to_string())),
            (
                "cbom.err.target_not_archive",
                Some("/tmp/x.bin".to_string()),
            ),
            ("cbom.err.empty_output", None),
        ] {
            let je = job_error_of(&CytraceError::Cbom {
                key,
                detail: detail.clone(),
            });
            assert_eq!(je.kind, "cbom", "kind 仍為機器可讀的分類");
            assert_eq!(
                je.i18n_key, key,
                "i18n_key 須為成因鍵——壓成 server.err.cbom 會讓「逾時」與「目標被拒」變成同一句話"
            );
            assert_eq!(
                je.detail,
                detail.unwrap_or_default(),
                "細節原樣帶出，不加前綴"
            );
        }
    }
}
