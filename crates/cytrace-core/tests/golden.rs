//! Golden-baseline 回歸測試（ADR-008 / NFR-02）。
//!
//! 釘選 fixture（grype + CycloneDX）→ 解析 → 組裝 → 與 golden 快照比對。
//! `meta` 用固定值（含 generated_at），排除非決定性欄位，故快照穩定（ADR-009）。
//! 升級引擎/改解析邏輯若改變輸出 → 本測試失敗，逼人複核。
//! 更新基準：`UPDATE_GOLDEN=1 cargo test -p cytrace-core --test golden`。

use cytrace_core::{assemble, parse};
use cytrace_types::{DbSnapshot, Meta, ToolVersions};

const GRYPE: &str = include_str!("fixtures/grype.json");
const CYCLONEDX: &str = include_str!("fixtures/cyclonedx.json");
const GOLDEN_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/golden/scanresult.json");

fn fixed_meta() -> Meta {
    Meta {
        target: "dir:/fixture".into(),
        tool_versions: ToolVersions {
            syft: "1.45.1".into(),
            grype: "0.114.0".into(),
            theia: None,
        },
        db_snapshot: DbSnapshot {
            version: "v6.1.7".into(),
            built: "2026-06-19".into(),
        },
        generated_at: "FIXED-FOR-GOLDEN".into(),
        scan_identity: None,
    }
}

#[test]
fn scanresult_matches_golden_baseline() {
    let components = parse::parse_cyclonedx(CYCLONEDX).unwrap();
    let findings = parse::parse_grype(GRYPE).unwrap();
    let result = assemble(fixed_meta(), components, findings);
    let actual = serde_json::to_string_pretty(&result).unwrap();

    if std::env::var("UPDATE_GOLDEN").is_ok() {
        std::fs::create_dir_all(std::path::Path::new(GOLDEN_PATH).parent().unwrap()).unwrap();
        std::fs::write(GOLDEN_PATH, format!("{actual}\n")).unwrap();
    }

    let expected =
        std::fs::read_to_string(GOLDEN_PATH).expect("golden 不存在；先以 UPDATE_GOLDEN=1 產生");
    assert_eq!(
        actual.trim(),
        expected.trim(),
        "輸出偏離 golden baseline——若為刻意變更，UPDATE_GOLDEN=1 重產並複核"
    );
}

const CBOM: &str = include_str!("fixtures/cbom.json");
const GOLDEN_CRYPTO_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/golden/scanresult-crypto.json"
);

/// 含 CBOM 的 golden（ADR-013 決策 7）：釘死 crypto 區段的序列化形態。
///
/// 特別要釘的是 `skip_serializing_if` 的行為——`None` 欄位不得序列化成 `null`，
/// 否則舊版消費者會讀到型別不符的值。
#[test]
fn scanresult_with_crypto_matches_golden_baseline() {
    use cytrace_types::{CbomStatus, CryptoInventory};

    let components = parse::parse_cyclonedx(CYCLONEDX).unwrap();
    let findings = parse::parse_grype(GRYPE).unwrap();
    let assets = parse::parse_cbom(CBOM).unwrap();
    let mut meta = fixed_meta();
    meta.tool_versions.theia = Some("1.1.2".into());
    meta.scan_identity = Some("uid=1000".into());
    let crypto = Some(CryptoInventory {
        status: CbomStatus::Completed,
        assets,
        unscanned_unreadable: 2,
        unscanned_oversize: 0,
        unscanned_undetermined: 0,
    });
    let result = cytrace_core::assemble_with_crypto(meta, components, findings, crypto);
    let actual = serde_json::to_string_pretty(&result).unwrap();

    if std::env::var("UPDATE_GOLDEN").is_ok() {
        std::fs::write(GOLDEN_CRYPTO_PATH, format!("{actual}\n")).unwrap();
    }

    let expected = std::fs::read_to_string(GOLDEN_CRYPTO_PATH)
        .expect("golden 不存在；先以 UPDATE_GOLDEN=1 產生");
    assert_eq!(
        actual.trim(),
        expected.trim(),
        "CBOM 輸出偏離 golden baseline——若為刻意變更，UPDATE_GOLDEN=1 重產並複核"
    );
    // 反空轉：`!contains(...)` 這族斷言在 actual 為空時全部恆真。
    // 先釘住輸出確實有內容與預期結構，那些否定式斷言才有意義（第十輪自盤點）。
    assert!(
        actual.contains("\"crypto\"") && actual.contains("\"assets\""),
        "golden 輸出缺少 crypto/assets 結構——fixture 或組裝可能失效，\
         下面的否定式斷言會全部恆真：{}",
        &actual[..actual.len().min(200)]
    );
    assert!(
        !actual.contains("PRIVATE KEY"),
        "NFR-09：golden 不得含金鑰內容"
    );
    assert!(
        !actual.contains("\"primitive\": null"),
        "None 不得序列化為 null"
    );
}
