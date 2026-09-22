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

    /// 對目標產生 CycloneDX CBOM（ADR-013）。
    ///
    /// **降級語意**（決策 4）：引擎 binary 不存在 → `Ok(None)`（不影響 SBOM/CVE 主流程）；
    /// 其餘失敗（子程序非零、輸出空白或非 JSON）→ `Err`，由呼叫端記為
    /// [`cytrace_types::CbomStatus::Failed`]，同樣不中止主流程。
    ///
    /// 預設實作回 `Ok(None)`，使既有 fake 引擎無須改動（測試縫相容）。
    fn cbom(&self, _target: &str) -> Result<Option<String>> {
        Ok(None)
    }
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
    fn cbom(&self, target: &str) -> Result<Option<String>> {
        cbom(target)
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

// ─── CBOM（cbomkit-theia；ADR-013）─────────────────────────────────

/// theia 的輸入形態。**只接受本地路徑**——registry 參照一律在此層拒絕（決策 2）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CbomTarget {
    /// 檔案系統目錄 → `theia dir <path>`
    Dir(std::path::PathBuf),
    /// docker-save tar / OCI layout（目錄或 tar）→ `theia image <path>`
    Image(std::path::PathBuf),
}

impl CbomTarget {
    /// theia 子命令名稱。
    pub fn subcommand(&self) -> &'static str {
        match self {
            CbomTarget::Dir(_) => "dir",
            CbomTarget::Image(_) => "image",
        }
    }
    /// 傳給 theia 的路徑。
    pub fn path(&self) -> &std::path::Path {
        match self {
            CbomTarget::Dir(p) | CbomTarget::Image(p) => p,
        }
    }
}

/// CyTrace 目標字串 → theia 輸入形態（ADR-013 決策 2）。
///
/// **必須實際開檔成功才轉譯**，不可僅做存在性判定：存在但不可讀的 tar 會讓 theia
/// 判定「本地取得失敗」而**回退嘗試 docker daemon / podman / containerd / registry**
/// （T901b 實測，stderr 可見 `index.docker.io`），在有網路的環境即違反零外連（NFR-01）。
///
/// 無法在本地判定的形態（裸映像名等）一律拒絕，**不猜測**。
pub fn cbom_target(target: &str) -> Result<CbomTarget> {
    // syft 風格前綴：取冒號後的路徑部分
    let raw = ["dir:", "docker-archive:", "oci-archive:", "oci-dir:"]
        .iter()
        .find_map(|p| target.strip_prefix(*p))
        .unwrap_or(target);

    let path = std::path::Path::new(raw);
    let meta = std::fs::metadata(path).map_err(|_| {
        CytraceError::Config(format!(
            "cbom.err.target_not_local（目標非本地可讀路徑，拒絕交給引擎）：{target}"
        ))
    })?;

    if meta.is_dir() {
        // 可讀性前檢：列目錄失敗即拒絕
        std::fs::read_dir(path).map_err(|_| {
            CytraceError::Config(format!(
                "cbom.err.target_unreadable（目錄不可讀）：{target}"
            ))
        })?;
        // OCI layout 目錄以標記檔辨識
        if path.join("oci-layout").exists() {
            return Ok(CbomTarget::Image(path.to_path_buf()));
        }
        return Ok(CbomTarget::Dir(path.to_path_buf()));
    }

    // 可讀性前檢：實際開檔
    std::fs::File::open(path).map_err(|_| {
        CytraceError::Config(format!(
            "cbom.err.target_unreadable（檔案不可讀）：{target}"
        ))
    })?;
    Ok(CbomTarget::Image(path.to_path_buf()))
}

/// 以 cbomkit-theia 對目標產生 CycloneDX CBOM（ADR-013）。
///
/// 硬性條件（決策 10，皆為 T901b 實測所得）：
/// - 目標先經 [`cbom_target`] 轉譯與**可讀性前檢**，不可讀即拒絕、不 spawn；
/// - 以**專用可寫 `HOME`** 啟動，否則 theia 會把警告印進 stdout 汙染 JSON；
/// - stdout 須通過 [`ensure_cbom_json`]，空白或非 JSON 一律視為失敗。
///
/// 回傳 `Ok(None)` 僅代表**引擎不存在**（降級）；其餘失敗回 `Err`。
pub fn cbom(target: &str) -> Result<Option<String>> {
    let t = cbom_target(target)?;

    // theia 需要可寫 HOME 才不會把警告印到 stdout（T901b 實測）
    let home = std::env::temp_dir().join(format!("cytrace-theia-home-{}", std::process::id()));
    std::fs::create_dir_all(&home)?;

    let out = Command::new("cbomkit-theia")
        .arg(t.subcommand())
        .arg(t.path())
        .env("HOME", &home)
        .output();

    let out = match out {
        Ok(o) => o,
        // 引擎不存在 → 降級（決策 4）；其餘 I/O 錯誤仍為失敗
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(CytraceError::Engine(format!("cbomkit-theia: {e}"))),
    };

    let stdout = check(out, "cbomkit-theia")?;
    ensure_cbom_json(&stdout)?;
    Ok(Some(stdout))
}

/// 驗證 theia stdout 為合法 JSON（ADR-013 決策 10）。
///
/// `HOME` 不可寫時 theia 會把警告印到 **stdout** 汙染輸出；輸入不可讀時則 **stdout 空白且 exit 0**。
/// 兩種情形都**不得**被當成「掃到 0 項」——一律視為失敗。
pub fn ensure_cbom_json(stdout: &str) -> Result<&str> {
    if stdout.trim().is_empty() {
        return Err(CytraceError::Parse(
            "cbom.err.empty_output（引擎輸出空白，非「零資產」）".into(),
        ));
    }
    serde_json::from_str::<serde_json::Value>(stdout).map_err(|e| {
        CytraceError::Parse(format!("cbom.err.stdout_not_json（輸出非合法 JSON）：{e}"))
    })?;
    Ok(stdout)
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

    // ── T905：CBOM 目標轉譯與可讀性前檢（ADR-013 決策 2/10）──

    use std::fs;
    use std::path::PathBuf;

    fn tmpdir(tag: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("cytrace-cbom-test-{}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).expect("建立暫存目錄");
        d
    }

    #[test]
    fn existing_directory_maps_to_dir_mode() {
        let d = tmpdir("dir");
        let t = cbom_target(d.to_str().unwrap()).expect("目錄須可轉譯");
        assert!(matches!(t, CbomTarget::Dir(_)));
        // syft 風格前綴亦須支援
        let t2 = cbom_target(&format!("dir:{}", d.display())).expect("dir: 前綴");
        assert!(matches!(t2, CbomTarget::Dir(_)));
    }

    #[test]
    fn existing_tar_maps_to_image_mode() {
        let d = tmpdir("tar");
        let tar = d.join("image.tar");
        fs::write(&tar, b"not really a tar").unwrap();
        assert!(matches!(
            cbom_target(tar.to_str().unwrap()).expect("tar"),
            CbomTarget::Image(_)
        ));
        assert!(matches!(
            cbom_target(&format!("docker-archive:{}", tar.display())).expect("前綴"),
            CbomTarget::Image(_)
        ));
    }

    #[test]
    fn oci_layout_directory_maps_to_image_mode() {
        let d = tmpdir("oci");
        fs::write(d.join("oci-layout"), br#"{"imageLayoutVersion":"1.0.0"}"#).unwrap();
        fs::create_dir_all(d.join("blobs")).unwrap();
        assert!(matches!(
            cbom_target(d.to_str().unwrap()).expect("OCI layout"),
            CbomTarget::Image(_)
        ));
    }

    #[test]
    fn bare_image_reference_is_rejected() {
        // ADR-013 決策 2：裸映像名會讓 theia 走 registry，零外連鐵則下一律拒絕
        for bare in ["nginx:latest", "ghcr.io/foo/bar:1.0", "alpine"] {
            assert!(
                cbom_target(bare).is_err(),
                "裸映像名 {bare} 必須被拒絕，不得交給 theia"
            );
        }
    }

    #[test]
    fn nonexistent_path_is_rejected() {
        assert!(cbom_target("/nonexistent/cytrace/xyz.tar").is_err());
    }

    #[test]
    #[cfg(unix)]
    fn unreadable_input_is_rejected_before_spawning_engine() {
        // ADR-013 新發現二：輸入不可讀時 theia 會回退嘗試 registry（隱含外連），
        // 且 stdout 空白仍 exit 0。故必須「實際開檔成功」才轉譯。
        use std::os::unix::fs::PermissionsExt;
        let d = tmpdir("unreadable");
        let tar = d.join("secret.tar");
        fs::write(&tar, b"x").unwrap();
        fs::set_permissions(&tar, fs::Permissions::from_mode(0o000)).unwrap();
        let result = cbom_target(tar.to_str().unwrap());
        // root 會無視權限位元，該情境下跳過斷言
        if fs::File::open(&tar).is_err() {
            assert!(result.is_err(), "不可讀的 tar 必須在 spawn 前被拒絕");
        }
    }

    // ── stdout 純淨度（ADR-013 決策 10）──

    #[test]
    fn polluted_stdout_is_rejected_as_failure() {
        // HOME 不可寫時 theia 會把警告印到 stdout，JSON 解析失敗但 exit 0
        let polluted = "could not create application folder '/nonexistent/.cbomkit-theia'\n{\"bomFormat\":\"CycloneDX\"}";
        assert!(ensure_cbom_json(polluted).is_err());
    }

    #[test]
    fn empty_stdout_is_rejected_not_treated_as_zero_assets() {
        // 輸入不可讀時 stdout 空白 + exit 0——絕不可映射為「掃到 0 項」
        assert!(ensure_cbom_json("").is_err());
        assert!(ensure_cbom_json("   \n").is_err());
    }

    #[test]
    fn valid_cbom_json_passes_through() {
        let good = r#"{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}"#;
        assert_eq!(ensure_cbom_json(good).expect("合法 JSON"), good);
    }
}
