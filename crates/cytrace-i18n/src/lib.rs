//! 輕量 i18n catalog（ADR-004）。語系資源**內嵌**進 binary（離線單一執行檔）。
//!
//! 與前端 react-i18next 共用同一組 `locales/*.json` 鍵與 `{{var}}` 插值語法；
//! 巢狀命名空間以 `a.b.c` 路徑查找；缺鍵 fallback 至 zh-TW。
//! CLI 與 server（ADR-011）共用本 crate（禁硬編碼使用者可見字串，NFR-06）。

use serde_json::Value;

const ZH_TW: &str = include_str!("../../../locales/zh-TW.json");
const EN_US: &str = include_str!("../../../locales/en-US.json");

/// 載入的雙語 catalog。
pub struct Catalog {
    lang: Value,
    fallback: Value,
}

impl Catalog {
    /// 依語言碼載入（"en-US"/"en" → 英文，其餘 → zh-TW）。fallback 永遠是 zh-TW。
    pub fn load(lang: &str) -> Self {
        let l = lang.to_ascii_lowercase();
        let primary = if l.starts_with("en") { EN_US } else { ZH_TW };
        Catalog {
            lang: serde_json::from_str(primary).expect("內嵌 locale 應為合法 JSON"),
            fallback: serde_json::from_str(ZH_TW).expect("內嵌 zh-TW 應為合法 JSON"),
        }
    }

    /// 取訊息並插值。缺鍵時退回 fallback，再缺則回鍵本身（方便察覺漏譯）。
    pub fn t(&self, key: &str, vars: &[(&str, &str)]) -> String {
        let raw = lookup(&self.lang, key)
            .or_else(|| lookup(&self.fallback, key))
            .unwrap_or_else(|| key.to_string());
        interpolate(&raw, vars)
    }

    /// 渲染 `CytraceError::Cbom`（純鍵 + 不可翻譯細節）為使用者可見訊息。
    ///
    /// 細節的變數名**由鍵決定**：`cbom.err.timeout` 的細節是秒數（`{{secs}}`），
    /// 其餘皆為目標路徑（`{{target}}`）。插值後若仍殘留佔位符、或細節根本沒被用上
    /// （鍵的文案未含該變數），才把細節補在括號內——否則會出現「佔位符原樣印出
    /// 且路徑重複一次」的畫面（第五輪修補造成、第六輪複審抓到的迴歸）。
    ///
    /// **CLI 與 server 共用本函式**：兩邊各寫一份渲染邏輯，就會有一邊先退化成裸鍵。
    pub fn render_cbom(&self, key: &str, detail: Option<&str>) -> String {
        let Some(d) = detail else {
            return self.t(key, &[]);
        };
        let vars: &[(&str, &str)] = if key == "cbom.err.timeout" {
            &[("secs", d)]
        } else {
            &[("target", d)]
        };
        let rendered = self.t(key, vars);
        if rendered.contains("{{") || !rendered.contains(d) {
            format!("{}（{d}）", self.t(key, &[]))
        } else {
            rendered
        }
    }
}

/// 巢狀路徑查找（"report.notes.title"）。
fn lookup(root: &Value, key: &str) -> Option<String> {
    let mut cur = root;
    for seg in key.split('.') {
        cur = cur.get(seg)?;
    }
    cur.as_str().map(|s| s.to_string())
}

/// `{{var}}` 插值（與 react-i18next 共用語法；不支援複數/context，見 ADR-004 共用值契約）。
fn interpolate(template: &str, vars: &[(&str, &str)]) -> String {
    let mut out = template.to_string();
    for (k, v) in vars {
        out = out.replace(&format!("{{{{{k}}}}}"), v);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_key_lookup_works() {
        let c = Catalog::load("zh-TW");
        assert_eq!(c.t("severity.critical", &[]), "極高");
        assert_eq!(c.t("report.notes.title", &[]), "附註");
    }

    #[test]
    fn english_catalog_selected() {
        let c = Catalog::load("en-US");
        assert_eq!(c.t("severity.critical", &[]), "Critical");
    }

    #[test]
    fn interpolation_substitutes_vars() {
        let c = Catalog::load("zh-TW");
        assert_eq!(
            c.t("cli.scanning", &[("target", "dir:/srv")]),
            "掃描中：dir:/srv"
        );
    }

    #[test]
    fn missing_key_returns_key_itself() {
        let c = Catalog::load("en-US");
        assert_eq!(c.t("no.such.key", &[]), "no.such.key");
    }
}
