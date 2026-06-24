//! 報表產生：把 [`ScanResult`] 依**資料注入契約**（ADR-009）注入內嵌單檔 HTML 樣板。
//!
//! 樣板＝M3 的 Vite 單檔 React bundle（`frontend/dist/index.html` → `assets/`），於編譯期以
//! `include_str!` 內嵌；產生時把 `<!--CYTRACE_DATA-->` 換成 `<script id="cytrace-data">` 資料 tag。

use cytrace_core::{CytraceError, Result};
use cytrace_types::ScanResult;

/// 注入點 sentinel（ADR-009）。Vite 樣板 head 內放同一個。
const DATA_SENTINEL: &str = "<!--CYTRACE_DATA-->";

/// 內嵌報表樣板（M3 單檔 build 產物）。以 `make frontend` 重產 frontend/dist/index.html → 複製到 assets/。
const EMBEDDED_TEMPLATE: &str = include_str!("../assets/report-template.html");

/// 把 JSON 字串轉為可安全置入 HTML `<script>` 區塊的形式（ADR-009 跳脫規則）。
///
/// - `</` → `<\/`（避免 `</script>` 提前關閉 script）
/// - U+2028 / U+2029（JS 行終止符）→ ` ` / ` `
fn escape_for_script(json: &str) -> String {
    json.replace("</", "<\\/")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029")
}

/// 依注入契約把 [`ScanResult`] 注入內嵌樣板，回傳自包含單檔 HTML 字串。
pub fn render(result: &ScanResult) -> Result<String> {
    render_with_template(result, EMBEDDED_TEMPLATE)
}

/// 同 [`render`]，但可指定樣板（供測試與 M3 內嵌樣板共用）。樣板須含 [`DATA_SENTINEL`]。
pub fn render_with_template(result: &ScanResult, template: &str) -> Result<String> {
    if !template.contains(DATA_SENTINEL) {
        return Err(CytraceError::Config(format!(
            "報表樣板缺少注入點 {DATA_SENTINEL}"
        )));
    }
    let json = serde_json::to_string(result)
        .map_err(|e| CytraceError::Parse(format!("序列化 ScanResult: {e}")))?;
    let tag = format!(
        "<script id=\"cytrace-data\" type=\"application/json\">{}</script>",
        escape_for_script(&json)
    );
    Ok(template.replace(DATA_SENTINEL, &tag))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cytrace_types::*;
    use std::collections::BTreeMap;

    fn sample() -> ScanResult {
        ScanResult {
            schema_version: SCHEMA_VERSION,
            meta: Meta {
                target: "dir:/srv/app".into(),
                tool_versions: ToolVersions {
                    syft: "1.0".into(),
                    grype: "0.74".into(),
                },
                db_snapshot: DbSnapshot {
                    version: "5".into(),
                    built: "2026-06-01".into(),
                },
                generated_at: "2026-06-24T00:00:00Z".into(),
            },
            components: vec![],
            findings: vec![Vulnerability {
                id: "CVE-2024-0001".into(),
                severity: Severity::High,
                cvss: Some(7.5),
                // 惡意元件名含 </script>，驗證跳脫
                component: "evil</script><b>".into(),
                fixed_version: None,
                source: "nvd".into(),
            }],
            summary: Summary {
                counts_by_severity: BTreeMap::new(),
                overall_risk: Severity::High,
            },
        }
    }

    #[test]
    fn injects_data_at_sentinel() {
        let html = render(&sample()).unwrap();
        assert!(html.contains("<script id=\"cytrace-data\" type=\"application/json\">"));
        assert!(!html.contains(DATA_SENTINEL), "sentinel 應已被替換");
        assert!(html.contains("CVE-2024-0001"));
    }

    #[test]
    fn escapes_closing_script_to_prevent_breakout() {
        let html = render(&sample()).unwrap();
        // 跳脫後不得出現裸 </script> 來自資料（只有結尾 tag 自己的）
        assert!(html.contains("<\\/script>"), "資料中的 </ 應被跳脫為 <\\/");
        // 內嵌資料段不可提前以 </script> 關閉：資料裡的 </script> 必須是 <\/script>
        let data_seg = html.split("type=\"application/json\">").nth(1).unwrap();
        let before_close = data_seg.split("</script>").next().unwrap();
        assert!(!before_close.contains("</script>"));
    }

    #[test]
    fn missing_sentinel_is_config_error() {
        let err = render_with_template(&sample(), "<html>no sentinel</html>").unwrap_err();
        assert!(matches!(err, CytraceError::Config(_)));
    }
}
