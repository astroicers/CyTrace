//! 報表產生：把 [`ScanResult`] 依**資料注入契約**（ADR-009）注入內嵌單檔 HTML 樣板。
//!
//! 樣板＝M3 的 Vite 單檔 React bundle（`frontend/dist/index.html` → `assets/`），於編譯期以
//! `include_str!` 內嵌；產生時把 `<!--CYTRACE_DATA-->` 換成 `<script id="cytrace-data">` 資料 tag，
//! 並把 `<html lang>` 設為產生時的語言——報表前端以它決定**開啟時**的語言（T918；檢視者仍可切換）。

use cytrace_core::{CytraceError, Result};
use cytrace_types::ScanResult;

/// 注入點 sentinel（ADR-009）。Vite 樣板 head 內放同一個。
const DATA_SENTINEL: &str = "<!--CYTRACE_DATA-->";

/// 樣板根元素（`frontend/index.html`）。產生時換成指定語言；必須恰好出現一次，
/// 否則前端拿不到產生語言、一律以 zh-TW 開啟，而這不會有任何錯誤訊息。
const HTML_LANG_MARKER: &str = "<html lang=\"zh-TW\">";

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
///
/// `lang` 為報表開啟時的語言（CLI 的 `--lang`／`CYTRACE_LANG`、server 的請求語系）；
/// 正規化規則同 [`cytrace_i18n::lang_code`]，不支援的值 → zh-TW。
pub fn render(result: &ScanResult, lang: &str) -> Result<String> {
    render_with_template(result, EMBEDDED_TEMPLATE, lang)
}

/// 同 [`render`]，但可指定樣板（供測試與 M3 內嵌樣板共用）。樣板須含 [`DATA_SENTINEL`]
/// 與恰好一個 [`HTML_LANG_MARKER`]。
pub fn render_with_template(result: &ScanResult, template: &str, lang: &str) -> Result<String> {
    if !template.contains(DATA_SENTINEL) {
        // 鍵值形式的診斷資料：untranslatable_detail 會原樣帶出這段內文到 API（經 runner）
        return Err(CytraceError::Config(format!(
            "template missing sentinel {DATA_SENTINEL}"
        )));
    }
    if template.matches(HTML_LANG_MARKER).count() != 1 {
        return Err(CytraceError::Config(format!(
            "template must contain exactly one {HTML_LANG_MARKER}"
        )));
    }
    let code = cytrace_i18n::lang_code(lang).unwrap_or("zh-TW");
    let template = template.replacen(HTML_LANG_MARKER, &format!("<html lang=\"{code}\">"), 1);
    let json = serde_json::to_string(result)
        .map_err(|e| CytraceError::Parse(format!("scan-result serialize: {e}")))?;
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
                    theia: None,
                },
                db_snapshot: DbSnapshot {
                    version: "5".into(),
                    built: "2026-06-01".into(),
                },
                generated_at: "2026-06-24T00:00:00Z".into(),
                scan_identity: None,
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
            crypto: None,
        }
    }

    /// 取報表根元素的 lang 值。
    fn html_lang(html: &str) -> &str {
        let rest = html.split("<html lang=\"").nth(1).expect("缺 <html lang>");
        rest.split('"').next().unwrap()
    }

    #[test]
    fn root_lang_follows_generation_language() {
        // 用**內嵌的實際樣板**：bundle 重建後若根元素的寫法變了，這裡就會紅（T918）
        assert_eq!(html_lang(&render(&sample(), "en-US").unwrap()), "en-US");
        assert_eq!(html_lang(&render(&sample(), "zh-TW").unwrap()), "zh-TW");
        // 正規化與 CLI 同一套規則；不支援 → zh-TW
        assert_eq!(html_lang(&render(&sample(), "en").unwrap()), "en-US");
        assert_eq!(html_lang(&render(&sample(), "fr-FR").unwrap()), "zh-TW");
        assert_eq!(html_lang(&render(&sample(), "").unwrap()), "zh-TW");
        let html = render(&sample(), "en-US").unwrap();
        assert_eq!(html.matches("<html").count(), 1, "根元素只能有一個");
    }

    #[test]
    fn lang_marker_must_appear_exactly_once() {
        let none = "<html><head><!--CYTRACE_DATA--></head></html>";
        let twice = "<html lang=\"zh-TW\"><!--CYTRACE_DATA--><html lang=\"zh-TW\">";
        for t in [none, twice] {
            let err = render_with_template(&sample(), t, "en-US").unwrap_err();
            assert!(matches!(err, CytraceError::Config(_)), "{t}");
        }
    }

    #[test]
    fn injects_data_at_sentinel() {
        let html = render(&sample(), "zh-TW").unwrap();
        assert!(html.contains("<script id=\"cytrace-data\" type=\"application/json\">"));
        assert!(!html.contains(DATA_SENTINEL), "sentinel 應已被替換");
        assert!(html.contains("CVE-2024-0001"));
    }

    #[test]
    fn escapes_closing_script_to_prevent_breakout() {
        let html = render(&sample(), "zh-TW").unwrap();
        // 跳脫後不得出現裸 </script> 來自資料（只有結尾 tag 自己的）
        assert!(html.contains("<\\/script>"), "資料中的 </ 應被跳脫為 <\\/");
        // 內嵌資料段不可提前以 </script> 關閉：資料裡的 </script> 必須是 <\/script>
        let data_seg = html.split("type=\"application/json\">").nth(1).unwrap();
        let before_close = data_seg.split("</script>").next().unwrap();
        assert!(!before_close.contains("</script>"));
    }

    #[test]
    fn missing_sentinel_is_config_error() {
        let err = render_with_template(&sample(), "<html>no sentinel</html>", "zh-TW").unwrap_err();
        assert!(matches!(err, CytraceError::Config(_)));
    }
}
