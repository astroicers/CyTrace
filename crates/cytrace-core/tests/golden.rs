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
        },
        db_snapshot: DbSnapshot {
            version: "v6.1.7".into(),
            built: "2026-06-19".into(),
        },
        generated_at: "FIXED-FOR-GOLDEN".into(),
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
