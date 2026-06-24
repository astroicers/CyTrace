//! Syft / Grype 子程序編排（SDS §3 / ADR-002/003）。
//!
//! 引擎為釘選版 Go binary，以子程序呼叫。Grype 強制離線：`GRYPE_DB_AUTO_UPDATE=false`、
//! `GRYPE_DB_VALIDATE_AGE=false`（否則舊快照會被年齡驗證中止，ADR-003）。
//!
//! 注意：本模組需安裝包內的引擎執行檔；無引擎時回 [`CytraceError::Engine`]，
//! 由 CLI 對映為非 2 的錯誤退出碼（與 fail-on 的 2 區隔）。

use cytrace_core::{CytraceError, Result};
use std::process::Command;

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
