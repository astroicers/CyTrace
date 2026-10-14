//! Windows 上的真引擎煙霧測試（T911）。
//!
//! `real_engine.rs` 整份限定 unix：它的案例依賴 symlink、FIFO、權限位元、openssl／ssh-keygen。
//! Windows 交付包從 T911 起內含交叉編譯的 `cbomkit-theia.exe`，但「編得出來」不等於「跑得起來」——
//! 例如 Go 在 Windows 上以 USERPROFILE 而非 HOME 找家目錄，環境沒給對就會把警告印進 stdout、
//! 汙染 JSON。本檔以真引擎跑最小的兩個情境，證明這條路徑在 Windows 上確實能用。
//!
//! 跑法（CI windows-package job）：`cbomkit-theia.exe`、`syft.exe`、`grype.exe` 在 PATH 上（包內 bin），
//! `cargo test -p cytrace-core --test real_engine_windows -- --ignored`。
//! 缺引擎時**失敗**，不靜默通過。

#![cfg(windows)]

use cytrace_core::collect_cbom;
use cytrace_core::engine::{RealEngine, ScanEngine};
use cytrace_types::CbomStatus;
use std::path::PathBuf;

const FIXTURE_CERT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/e2e-selfsigned.crt"
);

fn workspace(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("cytrace-rew-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn require_theia() {
    let present = std::process::Command::new("cbomkit-theia")
        .arg("--help")
        .output()
        .map(|o| o.status.success() || !o.stdout.is_empty())
        .unwrap_or(false);
    assert!(
        present,
        "cbomkit-theia 不在 PATH——本測試必須有引擎才算數，不得靜默通過"
    );
}

#[test]
#[ignore = "需要 cbomkit-theia.exe 在 PATH（CI windows-package job）"]
fn certificate_is_detected_on_windows() {
    require_theia();
    let dir = workspace("cert");
    std::fs::copy(FIXTURE_CERT, dir.join("server.crt")).unwrap();

    let inv = collect_cbom(&RealEngine, &dir.display().to_string());
    assert_eq!(inv.status, CbomStatus::Completed, "{inv:?}");
    assert!(
        inv.assets.iter().any(|a| a.asset_type == "certificate"),
        "應偵測到憑證：{:?}",
        inv.assets
    );
}

#[test]
#[ignore = "需要 cbomkit-theia.exe 在 PATH（CI windows-package job）"]
fn empty_directory_is_completed_with_zero_assets() {
    require_theia();
    let dir = workspace("empty");
    let inv = collect_cbom(&RealEngine, &dir.display().to_string());
    // 「完成且 0 項」與「失敗」必須可區分（ADR-013 決策 4）——stdout 被警告汙染時會落到 Failed
    assert_eq!(inv.status, CbomStatus::Completed, "{inv:?}");
    assert!(inv.assets.is_empty(), "{:?}", inv.assets);
}

/// #70：產品呼叫 Syft 時帶 `-c <暫存目錄\config.yaml>`。Windows 的暫存路徑（磁碟代號、反斜線）必須能被
/// syft.exe 解析，否則 Windows 交付包的每一次掃描都會失敗。經由 `RealEngine::sbom` 走產品的實際路徑。
#[test]
#[ignore = "需要 syft.exe 在 PATH（CI windows-package job）"]
fn syft_runs_with_isolated_config_on_windows() {
    let dir = workspace("syft-config");
    std::fs::write(dir.join("requirements.txt"), "requests==2.31.0\n").unwrap();
    let sbom = RealEngine
        .sbom(&format!("dir:{}", dir.display()))
        .expect("syft 以 -c 空設定檔執行失敗");
    let v: serde_json::Value = serde_json::from_str(&sbom).unwrap();
    assert!(
        v["components"]
            .as_array()
            .is_some_and(|c| c.iter().any(|x| x["name"] == "requests")),
        "應編目出 requests：{sbom}"
    );
}

/// #70：Grype 以同樣形態的 Windows 路徑載入空設定檔。CI 的 Windows 包不含漏洞 DB，無法跑比對，
/// 故以 `config --load` 確認 `-c` 的路徑可被 grype.exe 解析。
#[test]
#[ignore = "需要 grype.exe 在 PATH（CI windows-package job）"]
fn grype_loads_isolated_config_on_windows() {
    let dir = workspace("grype-config");
    let cfg = dir.join("config.yaml");
    std::fs::write(&cfg, "").unwrap();
    let out = std::process::Command::new("grype")
        .args(["config", "--load", "-c"])
        .arg(&cfg)
        .output()
        .expect("grype 不在 PATH——本測試必須有引擎才算數，不得靜默通過");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}
