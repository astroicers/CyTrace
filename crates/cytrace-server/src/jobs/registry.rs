//! Job registry：in-memory 索引 + `jobs/<id>/job.json` 原子落盤（tmp+rename）。
//!
//! 重啟恢復：走訪 `jobs/*/job.json` 重建索引；非終態 → `interrupted`；
//! 損毀的 job.json → 目錄改名 `.corrupt` 隔離、不擋啟動。
//!
//! 寫到終端機的訊息（隔離、落盤失敗）用操作者語言（`server.runtime.*`，T912）。

use super::{JobError, JobRecord, JobStatus};
use crate::error::Lang;
use cytrace_i18n::Localized;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

pub struct JobRegistry {
    jobs_dir: PathBuf,
    inner: RwLock<HashMap<String, JobRecord>>,
    /// 操作者語言（終端機訊息用；與 API 回應的語言無關）。
    lang: Lang,
}

impl JobRegistry {
    /// 開啟（建立目錄）並執行重啟恢復；恢復過程的通知印到 stderr。
    pub fn open(data_dir: &Path, lang: Lang) -> Result<Self, Localized> {
        let jobs_dir = data_dir.join("jobs");
        std::fs::create_dir_all(&jobs_dir).map_err(|e| {
            Localized::new("server.startup.data_dir_failed")
                .var("path", jobs_dir.display().to_string())
                .var("detail", e.to_string())
        })?;
        let reg = JobRegistry {
            jobs_dir,
            inner: RwLock::new(HashMap::new()),
            lang,
        };
        for notice in reg.recover()? {
            reg.report(&notice);
        }
        Ok(reg)
    }

    /// 以操作者語言印一則執行期訊息到 stderr。
    fn report(&self, notice: &Localized) {
        eprintln!("cytrace-server: {}", notice.render(self.lang.catalog()));
    }

    /// 重建索引。回傳要告知操作者的事件（隔離、落盤失敗），由 `open` 印出——分開是為了可測。
    fn recover(&self) -> Result<Vec<Localized>, Localized> {
        let entries = std::fs::read_dir(&self.jobs_dir).map_err(|e| {
            Localized::new("server.startup.data_dir_unreadable")
                .var("path", self.jobs_dir.display().to_string())
                .var("detail", e.to_string())
        })?;
        let mut notices = Vec::new();
        for entry in entries.flatten() {
            let dir = entry.path();
            if !dir.is_dir() || dir.extension().map(|e| e == "corrupt").unwrap_or(false) {
                continue;
            }
            let json_path = dir.join("job.json");
            // 讀不到與讀得到但解析失敗，告知操作者的原因不同
            let parsed = match std::fs::read_to_string(&json_path) {
                Ok(s) => serde_json::from_str::<JobRecord>(&s).map_err(|e| Some(e.to_string())),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(None),
                Err(e) => Err(Some(e.to_string())),
            };
            match parsed {
                Ok(mut record) => {
                    if !record.status.is_terminal() {
                        record.status = JobStatus::Interrupted;
                        record.finished_at = Some(super::now_iso());
                        record.error = Some(JobError {
                            kind: "interrupted".into(),
                            i18n_key: "server.job.interrupted".into(),
                            detail: String::new(),
                        });
                        if let Err(e) = self.persist_to(&dir, &record) {
                            notices.push(
                                Localized::new("server.runtime.job_persist_failed")
                                    .var("id", record.id.as_str())
                                    .var("detail", e.to_string()),
                            );
                        }
                    }
                    if let Ok(mut map) = self.inner.write() {
                        map.insert(record.id.clone(), record);
                    }
                }
                Err(cause) => {
                    // 損毀：隔離、不擋啟動。改名成功才說「已隔離」
                    let corrupt = dir.with_extension("corrupt");
                    let notice = match std::fs::rename(&dir, &corrupt) {
                        Ok(()) => match cause {
                            None => Localized::new("server.runtime.job_quarantined_missing")
                                .var("to", corrupt.display().to_string()),
                            Some(detail) => {
                                Localized::new("server.runtime.job_quarantined_corrupt")
                                    .var("to", corrupt.display().to_string())
                                    .var("detail", detail)
                            }
                        },
                        Err(e) => Localized::new("server.runtime.job_quarantine_failed")
                            .var("path", dir.display().to_string())
                            .var("detail", e.to_string()),
                    };
                    notices.push(notice);
                }
            }
        }
        Ok(notices)
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
            self.report(
                &Localized::new("server.runtime.job_persist_failed")
                    .var("id", id)
                    .var("detail", e.to_string()),
            );
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
            self.report(
                &Localized::new("server.runtime.job_persist_failed")
                    .var("id", id)
                    .var("detail", e.to_string()),
            );
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
        let reg = JobRegistry::open(&dir, Lang::ZhTw).unwrap();
        let mut record = JobRecord::new("mounted:t/x".into(), None).unwrap();
        record.status = JobStatus::Done;
        let id = record.id.clone();
        reg.insert(record).unwrap();

        // 重開：終態原樣載回
        let reg2 = JobRegistry::open(&dir, Lang::ZhTw).unwrap();
        assert_eq!(reg2.get(&id).unwrap().status, JobStatus::Done);
    }

    #[test]
    fn restart_marks_non_terminal_as_interrupted() {
        let dir = tmpdir("reg2");
        let reg = JobRegistry::open(&dir, Lang::ZhTw).unwrap();
        let record = JobRecord::new("mounted:t/x".into(), None).unwrap();
        let id = record.id.clone();
        reg.insert(record).unwrap();
        reg.update(&id, |r| r.status = JobStatus::Running);

        let reg2 = JobRegistry::open(&dir, Lang::ZhTw).unwrap();
        let r = reg2.get(&id).unwrap();
        assert_eq!(r.status, JobStatus::Interrupted);
        assert_eq!(r.error.unwrap().i18n_key, "server.job.interrupted");
        // interrupted 已落盤（再重開仍是 interrupted，且不再改寫 finished_at）
        let reg3 = JobRegistry::open(&dir, Lang::ZhTw).unwrap();
        assert_eq!(reg3.get(&id).unwrap().status, JobStatus::Interrupted);
    }

    /// 不經 `open` 的 registry——直接取 `recover` 的通知（`open` 會把它們印掉）。
    fn bare(dir: &Path) -> JobRegistry {
        let jobs_dir = dir.join("jobs");
        std::fs::create_dir_all(&jobs_dir).unwrap();
        JobRegistry {
            jobs_dir,
            inner: RwLock::new(HashMap::new()),
            lang: Lang::ZhTw,
        }
    }

    #[test]
    fn quarantine_notices_distinguish_missing_from_corrupt() {
        let dir = tmpdir("reg6");
        let jobs = dir.join("jobs");
        std::fs::create_dir_all(jobs.join("1-missing")).unwrap();
        std::fs::create_dir_all(jobs.join("2-bad")).unwrap();
        std::fs::write(jobs.join("2-bad").join("job.json"), "{not json").unwrap();

        let mut notices = bare(&dir).recover().unwrap();
        notices.sort_by_key(|n| n.key);
        let keys: Vec<_> = notices.iter().map(|n| n.key).collect();
        assert_eq!(
            keys,
            [
                "server.runtime.job_quarantined_corrupt",
                "server.runtime.job_quarantined_missing"
            ]
        );
        // 解析錯誤的細節要帶給操作者
        assert!(notices[0]
            .vars
            .iter()
            .any(|(k, v)| *k == "detail" && !v.is_empty()));
        assert!(jobs.join("1-missing.corrupt").is_dir());
        assert!(jobs.join("2-bad.corrupt").is_dir());
    }

    #[test]
    fn failed_quarantine_is_not_reported_as_quarantined() {
        let dir = tmpdir("reg7");
        let jobs = dir.join("jobs");
        std::fs::create_dir_all(jobs.join("3-bad")).unwrap();
        std::fs::write(jobs.join("3-bad").join("job.json"), "x").unwrap();
        // 目標已存在且非空 → rename 失敗（Linux ENOTEMPTY；Windows 亦拒絕覆蓋目錄）
        std::fs::create_dir_all(jobs.join("3-bad.corrupt").join("occupied")).unwrap();

        let notices = bare(&dir).recover().unwrap();
        assert_eq!(notices.len(), 1);
        assert_eq!(notices[0].key, "server.runtime.job_quarantine_failed");
        assert!(jobs.join("3-bad").join("job.json").exists());
    }

    #[test]
    fn interrupted_persist_failure_is_reported() {
        let dir = tmpdir("reg8");
        let mut record = JobRecord::new("t".into(), None).unwrap();
        record.status = JobStatus::Running;
        let job = dir.join("jobs").join(&record.id);
        std::fs::create_dir_all(&job).unwrap();
        std::fs::write(
            job.join("job.json"),
            serde_json::to_string(&record).unwrap(),
        )
        .unwrap();
        // tmp 檔位置被目錄佔住 → 寫入失敗（不依賴權限，root 執行亦然）
        std::fs::create_dir_all(job.join("job.json.tmp")).unwrap();

        let reg = bare(&dir);
        let notices = reg.recover().unwrap();
        assert_eq!(notices.len(), 1);
        assert_eq!(notices[0].key, "server.runtime.job_persist_failed");
        // 落盤失敗不影響本次啟動的索引
        assert_eq!(reg.get(&record.id).unwrap().status, JobStatus::Interrupted);
    }

    #[test]
    fn unwritable_data_dir_is_a_startup_error() {
        let dir = tmpdir("reg9");
        // data_dir/jobs 被一般檔案佔住 → create_dir_all 失敗
        std::fs::write(dir.join("jobs"), "").unwrap();
        let err = JobRegistry::open(&dir, Lang::ZhTw).err().unwrap();
        assert_eq!(err.key, "server.startup.data_dir_failed");
    }

    #[test]
    fn corrupt_job_json_is_quarantined() {
        let dir = tmpdir("reg3");
        let bad = dir.join("jobs").join("123-deadbeef");
        std::fs::create_dir_all(&bad).unwrap();
        std::fs::write(bad.join("job.json"), "{not json").unwrap();

        let reg = JobRegistry::open(&dir, Lang::ZhTw).unwrap();
        assert!(reg.get("123-deadbeef").is_none());
        assert!(dir.join("jobs").join("123-deadbeef.corrupt").exists());
    }

    #[test]
    fn cancel_only_when_queued() {
        let dir = tmpdir("reg4");
        let reg = JobRegistry::open(&dir, Lang::ZhTw).unwrap();
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
        let reg = JobRegistry::open(&dir, Lang::ZhTw).unwrap();
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
