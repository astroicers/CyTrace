//! Syft / Grype 子程序編排（SDS §3 / ADR-002/003）。
//!
//! 引擎為釘選版 Go binary，以子程序呼叫。Grype 強制離線：`GRYPE_DB_AUTO_UPDATE=false`、
//! `GRYPE_DB_VALIDATE_AGE=false`（否則舊快照會被年齡驗證中止，ADR-003）。
//!
//! 注意：本模組需安裝包內的引擎執行檔；無引擎時回 [`CytraceError::Engine`]，
//! 由 CLI 對映為非 2 的錯誤退出碼（與 fail-on 的 2 區隔）。
//!
//! [`ScanEngine`] trait 是 CLI 與 server（ADR-011）共用的測試縫：
//! 整合測試可注入 fake 實作，完全不需要 syft/grype binary（air-gapped CI 可跑）。

use crate::error::{CytraceError, Result};
use std::process::Command;

/// 掃描引擎抽象（測試縫）：真實實作為 [`RealEngine`]（子程序呼叫釘選版 syft/grype）。
pub trait ScanEngine: Send + Sync {
    /// 對目標產生 CycloneDX JSON SBOM。
    fn sbom(&self, target: &str) -> Result<String>;
    /// 對 SBOM（CycloneDX JSON）比對 CVE，回傳 grype JSON。
    fn vuln(&self, sbom_cyclonedx_json: &str) -> Result<String>;
}

/// 以子程序呼叫釘選版 syft/grype 的真實引擎。
pub struct RealEngine;

impl ScanEngine for RealEngine {
    fn sbom(&self, target: &str) -> Result<String> {
        sbom(target)
    }
    fn vuln(&self, sbom_cyclonedx_json: &str) -> Result<String> {
        vuln(sbom_cyclonedx_json)
    }
}

/// 以 Syft 對目標產生 CycloneDX JSON SBOM。
pub fn sbom(target: &str) -> Result<String> {
    let out = Command::new("syft")
        .args(["scan", target, "-o", "cyclonedx-json", "-q"])
        .output()
        .map_err(|e| CytraceError::Engine(format!("syft: {e}")))?;
    check(out, "syft")
}

/// 以 Grype 對 SBOM（CycloneDX JSON）比對 CVE，回傳 grype JSON。離線設定已內建。
///
/// 注意：grype 的 `sbom:-`（stdin）在部分版本不穩，故將 SBOM 寫入暫存檔以 `sbom:<path>` 餵入，
/// 亦避免 stdin/stdout pipe 滿載 deadlock。暫存檔用後即刪。
pub fn vuln(sbom_cyclonedx_json: &str) -> Result<String> {
    let tmp = std::env::temp_dir().join(format!("cytrace-sbom-{}.cdx.json", std::process::id()));
    std::fs::write(&tmp, sbom_cyclonedx_json)?;
    let out = Command::new("grype")
        .arg(format!("sbom:{}", tmp.display()))
        .args(["-o", "json", "-q"])
        .env("GRYPE_DB_AUTO_UPDATE", "false")
        .env("GRYPE_DB_VALIDATE_AGE", "false")
        .output();
    let _ = std::fs::remove_file(&tmp);
    let out = out.map_err(|e| CytraceError::Engine(format!("grype: {e}")))?;
    check(out, "grype")
}

fn check(out: std::process::Output, name: &str) -> Result<String> {
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(CytraceError::Engine(format!(
            "{name} 失敗（exit {:?}）：{}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// fake 引擎可經 `dyn ScanEngine` 注入——驗證測試縫成立（server 整合測試依賴此性質）。
    struct FakeEngine;

    impl ScanEngine for FakeEngine {
        fn sbom(&self, _target: &str) -> Result<String> {
            Ok("{}".into())
        }
        fn vuln(&self, _sbom: &str) -> Result<String> {
            Ok("{\"matches\":[]}".into())
        }
    }

    #[test]
    fn fake_engine_usable_through_trait_object() {
        let engine: &dyn ScanEngine = &FakeEngine;
        assert_eq!(engine.sbom("dir:/x").unwrap(), "{}");
        assert_eq!(engine.vuln("{}").unwrap(), "{\"matches\":[]}");
    }
}
