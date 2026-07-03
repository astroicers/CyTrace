//! Job 模型（ADR-011 §5）：無資料庫——檔案系統是唯一狀態真相。
//!
//! 狀態機：`queued → running → done/failed`；`queued --cancel--> canceled`；
//! 伺服器重啟時非終態一律轉 `interrupted`（不自動重跑，確定性優先）。

pub mod registry;
pub mod runner;

use cytrace_types::Summary;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    Queued,
    Running,
    Done,
    Failed,
    Canceled,
    Interrupted,
}

impl JobStatus {
    pub fn is_terminal(self) -> bool {
        !matches!(self, JobStatus::Queued | JobStatus::Running)
    }
}

/// job 失敗資訊（≙ CLI exit 1；`failon_triggered` 是狀態不是錯誤）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobError {
    pub kind: String,
    pub i18n_key: String,
    pub detail: String,
}

/// job 記錄（`jobs/<id>/job.json` 持久化；也是 API 回應形）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobRecord {
    pub id: String,
    pub status: JobStatus,
    /// 目標描述（`mounted:<root>/<path>` 或 `upload:<檔名>`）。
    pub target: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fail_on: Option<String>,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<Summary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failon_triggered: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JobError>,
}

impl JobRecord {
    pub fn new(target: String, fail_on: Option<String>) -> anyhow::Result<Self> {
        Ok(JobRecord {
            id: new_job_id()?,
            status: JobStatus::Queued,
            target,
            fail_on,
            created_at: now_iso(),
            started_at: None,
            finished_at: None,
            summary: None,
            failon_triggered: None,
            error: None,
        })
    }
}

/// `<epoch_secs>-<8hex>`：天然可排序（新→舊 = 字典序反向）。
fn new_job_id() -> anyhow::Result<String> {
    let mut raw = [0u8; 4];
    getrandom::getrandom(&mut raw).map_err(|e| anyhow::anyhow!("getrandom: {e}"))?;
    let hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    Ok(format!("{}-{}", cytrace_core::timefmt::epoch_secs(), hex))
}

pub(crate) fn now_iso() -> String {
    cytrace_core::timefmt::epoch_to_iso(cytrace_core::timefmt::epoch_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn job_id_is_sortable_epoch_prefixed() {
        let id = new_job_id().unwrap();
        let (epoch, hex) = id.split_once('-').unwrap();
        assert!(epoch.parse::<u64>().is_ok());
        assert_eq!(hex.len(), 8);
    }

    #[test]
    fn terminal_states() {
        assert!(!JobStatus::Queued.is_terminal());
        assert!(!JobStatus::Running.is_terminal());
        for s in [
            JobStatus::Done,
            JobStatus::Failed,
            JobStatus::Canceled,
            JobStatus::Interrupted,
        ] {
            assert!(s.is_terminal());
        }
    }

    #[test]
    fn record_serializes_without_null_noise() {
        let r = JobRecord::new("mounted:targets/app".into(), Some("high".into())).unwrap();
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"status\":\"queued\""));
        assert!(!json.contains("started_at")); // None 欄位不輸出
    }
}
