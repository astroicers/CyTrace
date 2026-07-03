//! Job registry：in-memory 索引 + `jobs/<id>/job.json` 原子落盤（tmp+rename）。
//!
//! 重啟恢復：走訪 `jobs/*/job.json` 重建索引；非終態 → `interrupted`；
//! 損毀的 job.json → 目錄改名 `.corrupt` 隔離、不擋啟動。

use super::{JobError, JobRecord, JobStatus};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

pub struct JobRegistry {
    jobs_dir: PathBuf,
    inner: RwLock<HashMap<String, JobRecord>>,
}

impl JobRegistry {
    /// 開啟（建立目錄）並執行重啟恢復。
    pub fn open(data_dir: &Path) -> anyhow::Result<Self> {
        let jobs_dir = data_dir.join("jobs");
        std::fs::create_dir_all(&jobs_dir)
            .map_err(|e| anyhow::anyhow!("無法建立資料目錄 {}：{e}", jobs_dir.display()))?;
        let reg = JobRegistry {
            jobs_dir,
            inner: RwLock::new(HashMap::new()),
        };
        reg.recover()?;
        Ok(reg)
    }

    fn recover(&self) -> anyhow::Result<()> {
        let entries = std::fs::read_dir(&self.jobs_dir)?;
        for entry in entries.flatten() {
            let dir = entry.path();
            if !dir.is_dir() || dir.extension().map(|e| e == "corrupt").unwrap_or(false) {
                continue;
            }
            let json_path = dir.join("job.json");
            let parsed = std::fs::read_to_string(&json_path)
                .ok()
                .and_then(|s| serde_json::from_str::<JobRecord>(&s).ok());
            match parsed {
                Some(mut record) => {
                    if !record.status.is_terminal() {
                        record.status = JobStatus::Interrupted;
                        record.finished_at = Some(super::now_iso());
                        record.error = Some(JobError {
                            kind: "interrupted".into(),
                            i18n_key: "server.job.interrupted".into(),
                            detail: String::new(),
                        });
                        let _ = self.persist_to(&dir, &record);
                    }
                    if let Ok(mut map) = self.inner.write() {
                        map.insert(record.id.clone(), record);
                    }
                }
                None => {
                    // 損毀：隔離、記 log、不擋啟動
                    let corrupt = dir.with_extension("corrupt");
                    eprintln!(
                        "cytrace-server: 損毀的 job 記錄，隔離至 {}",
                        corrupt.display()
                    );
                    let _ = std::fs::rename(&dir, &corrupt);
                }
            }
        }
        Ok(())
    }

    pub fn job_dir(&self, id: &str) -> PathBuf {
        self.jobs_dir.join(id)
    }

    fn persist_to(&self, dir: &Path, record: &JobRecord) -> anyhow::Result<()> {
        std::fs::create_dir_all(dir)?;
        let tmp = dir.join("job.json.tmp");
        std::fs::write(&tmp, serde_json::to_string_pretty(record)?)?;
        std::fs::rename(&tmp, dir.join("job.json"))?;
        Ok(())
    }

    /// 新增 job（索引 + 落盤）。
    pub fn insert(&self, record: JobRecord) -> anyhow::Result<()> {
        self.persist_to(&self.job_dir(&record.id), &record)?;
        if let Ok(mut map) = self.inner.write() {
            map.insert(record.id.clone(), record);
        }
        Ok(())
    }

    pub fn get(&self, id: &str) -> Option<JobRecord> {
        self.inner.read().ok()?.get(id).cloned()
    }

    /// 狀態轉移（f 就地修改後落盤）。job 不存在回 None。
    pub fn update<F: FnOnce(&mut JobRecord)>(&self, id: &str, f: F) -> Option<JobRecord> {
        let mut map = self.inner.write().ok()?;
        let record = map.get_mut(id)?;
        f(record);
        let snapshot = record.clone();
        drop(map);
        if let Err(e) = self.persist_to(&self.job_dir(id), &snapshot) {
            eprintln!("cytrace-server: job.json 落盤失敗（{id}）：{e}");
        }
        Some(snapshot)
    }

    /// 僅當 job 仍為 queued 時轉 canceled（供 DELETE 與 runner 取票後複查）。
    pub fn cancel_if_queued(&self, id: &str) -> bool {
        let Ok(mut map) = self.inner.write() else {
            return false;
        };
        let Some(record) = map.get_mut(id) else {
            return false;
        };
        if record.status != JobStatus::Queued {
            return false;
        }
        record.status = JobStatus::Canceled;
        record.finished_at = Some(super::now_iso());
        let snapshot = record.clone();
        drop(map);
        if let Err(e) = self.persist_to(&self.job_dir(id), &snapshot) {
            eprintln!("cytrace-server: job.json 落盤失敗（{id}）：{e}");
        }
        true
    }

    /// 刪除終態 job（目錄 + 索引）。running/queued 不可刪（呼叫端把關）。
    pub fn remove(&self, id: &str) -> anyhow::Result<()> {
        let dir = self.job_dir(id);
        if dir.exists() {
            std::fs::remove_dir_all(&dir)?;
        }
        if let Ok(mut map) = self.inner.write() {
            map.remove(id);
        }
        Ok(())
    }

    /// 列表（時間倒序）＋總數；`status` 過濾、limit/offset 分頁。
    pub fn list(
        &self,
        status: Option<JobStatus>,
        limit: usize,
        offset: usize,
    ) -> (Vec<JobRecord>, usize) {
        let Ok(map) = self.inner.read() else {
            return (vec![], 0);
        };
        let mut all: Vec<&JobRecord> = map
            .values()
            .filter(|r| status.map(|s| r.status == s).unwrap_or(true))
            .collect();
        all.sort_by(|a, b| b.id.cmp(&a.id));
        let total = all.len();
        let page = all.into_iter().skip(offset).take(limit).cloned().collect();
        (page, total)
    }

    /// 非終態（queued + running）數量——佇列上限檢查用。
    pub fn active_count(&self) -> usize {
        self.inner
            .read()
            .map(|m| m.values().filter(|r| !r.status.is_terminal()).count())
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("cytrace-test-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn insert_persist_reload_roundtrip() {
        let dir = tmpdir("reg1");
        let reg = JobRegistry::open(&dir).unwrap();
        let mut record = JobRecord::new("mounted:t/x".into(), None).unwrap();
        record.status = JobStatus::Done;
        let id = record.id.clone();
        reg.insert(record).unwrap();

        // 重開：終態原樣載回
        let reg2 = JobRegistry::open(&dir).unwrap();
        assert_eq!(reg2.get(&id).unwrap().status, JobStatus::Done);
    }

    #[test]
    fn restart_marks_non_terminal_as_interrupted() {
        let dir = tmpdir("reg2");
        let reg = JobRegistry::open(&dir).unwrap();
        let record = JobRecord::new("mounted:t/x".into(), None).unwrap();
        let id = record.id.clone();
        reg.insert(record).unwrap();
        reg.update(&id, |r| r.status = JobStatus::Running);

        let reg2 = JobRegistry::open(&dir).unwrap();
        let r = reg2.get(&id).unwrap();
        assert_eq!(r.status, JobStatus::Interrupted);
        assert_eq!(r.error.unwrap().i18n_key, "server.job.interrupted");
        // interrupted 已落盤（再重開仍是 interrupted，且不再改寫 finished_at）
        let reg3 = JobRegistry::open(&dir).unwrap();
        assert_eq!(reg3.get(&id).unwrap().status, JobStatus::Interrupted);
    }

    #[test]
    fn corrupt_job_json_is_quarantined() {
        let dir = tmpdir("reg3");
        let bad = dir.join("jobs").join("123-deadbeef");
        std::fs::create_dir_all(&bad).unwrap();
        std::fs::write(bad.join("job.json"), "{not json").unwrap();

        let reg = JobRegistry::open(&dir).unwrap();
        assert!(reg.get("123-deadbeef").is_none());
        assert!(dir.join("jobs").join("123-deadbeef.corrupt").exists());
    }

    #[test]
    fn cancel_only_when_queued() {
        let dir = tmpdir("reg4");
        let reg = JobRegistry::open(&dir).unwrap();
        let record = JobRecord::new("t".into(), None).unwrap();
        let id = record.id.clone();
        reg.insert(record).unwrap();
        assert!(reg.cancel_if_queued(&id));
        assert!(!reg.cancel_if_queued(&id)); // 已 canceled
        assert_eq!(reg.get(&id).unwrap().status, JobStatus::Canceled);
    }

    #[test]
    fn list_orders_newest_first_and_paginates() {
        let dir = tmpdir("reg5");
        let reg = JobRegistry::open(&dir).unwrap();
        for i in 0..3 {
            let mut r = JobRecord::new(format!("t{i}"), None).unwrap();
            r.id = format!("{}-0000000{i}", 1_000_000 + i);
            reg.insert(r).unwrap();
        }
        let (page, total) = reg.list(None, 2, 0);
        assert_eq!(total, 3);
        assert_eq!(page.len(), 2);
        assert!(page[0].id > page[1].id);
        let (q, _) = reg.list(Some(JobStatus::Done), 10, 0);
        assert!(q.is_empty());
    }
}
