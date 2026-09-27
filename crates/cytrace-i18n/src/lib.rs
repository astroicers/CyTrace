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
    /// 是否為英文語系。用於選擇標點字形（半角 vs 全角），不靠猜譯文內容。
    is_en: bool,
}

impl Catalog {
    /// 依語言碼載入（"en-US"/"en" → 英文，其餘 → zh-TW）。fallback 永遠是 zh-TW。
    pub fn load(lang: &str) -> Self {
        let l = lang.to_ascii_lowercase();
        let is_en = l.starts_with("en");
        let primary = if is_en { EN_US } else { ZH_TW };
        Catalog {
            lang: serde_json::from_str(primary).expect("內嵌 locale 應為合法 JSON"),
            fallback: serde_json::from_str(ZH_TW).expect("內嵌 zh-TW 應為合法 JSON"),
            is_en,
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
        let var = if key == "cbom.err.timeout" {
            "secs"
        } else {
            "target"
        };
        // 以**原文是否含該佔位符**決定走插值或括號，而非事後猜「細節有沒有出現在結果裡」。
        // 舊版用 `!rendered.contains(d)` 判斷，有兩個錯法（第七輪複審 finding）：
        // 細節恰為譯文子字串時會被誤判為「已插值」而**靜默丟棄**；`detail = Some("")`
        // （`cbom_target("")` 可達）則渲染出結尾懸空的「：」。
        let raw = lookup(&self.lang, key)
            .or_else(|| lookup(&self.fallback, key))
            .unwrap_or_else(|| key.to_string());
        if d.is_empty() {
            // 空細節不帶任何資訊，附上只會留一個懸空的分隔符
            return interpolate(&raw, &[(var, "?")]);
        }
        if raw.contains(&format!("{{{{{var}}}}}")) {
            interpolate(&raw, &[(var, d)])
        } else {
            // 鍵的文案沒有該變數的位置 → 細節補在括號內，不讓它消失。
            // **括號依語系選用**：寫死全角「（）」會讓 en-US 訊息夾全角標點
            // （node 實測抓到：`Engine error（/path）`）。
            let (open, close) = self.parens();
            format!("{}{open}{d}{close}", interpolate(&raw, &[]))
        }
    }

    /// 附加括號的字形。en-US 用半角，zh-TW 用全角。
    ///
    /// 依 `load()` already 算出的語系旗標，不靠探測譯文內容——用「某個鍵是否全 ASCII」
    /// 猜語系的話，英文文案哪天加個破折號就會誤判成中文。
    fn parens(&self) -> (&'static str, &'static str) {
        if self.is_en {
            (" (", ")")
        } else {
            ("（", "）")
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

    // ── render_cbom 的兩個邊界（第七輪複審 finding）──

    #[test]
    fn render_cbom_keeps_detail_even_when_it_matches_the_message_text() {
        // 舊版以 `!rendered.contains(detail)` 判斷是否已插值。當細節恰為譯文的子字串時，
        // 該判斷成立而細節被**靜默丟棄**——操作員失去唯一的處置線索。
        let c = Catalog::load("zh-TW");
        // 取一個文案含 {{target}} 的鍵，餵一個必然出現在譯文裡的短字串
        let msg = c.t("cbom.err.target_not_archive", &[]);
        let needle: String = msg.chars().take(2).collect();
        let out = c.render_cbom("cbom.err.target_not_archive", Some(&needle));
        assert!(!out.contains("{{"), "不得殘留佔位符：{out}");
        assert!(
            out.matches(&needle).count() >= 2,
            "細節須出現在插值位置（訊息本身已含該字串，故總數 ≥ 2）：{out}"
        );
    }

    #[test]
    fn render_cbom_handles_empty_detail_without_dangling_separator() {
        // `cbom_target("")` 會產生 detail = Some("")；直接插值會留下懸空的分隔符
        let c = Catalog::load("zh-TW");
        let out = c.render_cbom("cbom.err.target_not_archive", Some(""));
        assert!(!out.contains("{{"), "不得殘留佔位符：{out}");
        assert!(
            !out.ends_with('：') && !out.ends_with("（）"),
            "不得留懸空分隔符：{out}"
        );
        assert!(!out.is_empty());
    }

    #[test]
    fn render_cbom_falls_back_to_parentheses_when_the_key_has_no_placeholder() {
        // 文案沒有變數位置時，細節仍不得消失
        let c = Catalog::load("zh-TW");
        let out = c.render_cbom("cbom.err.empty_output", Some("/tmp/x"));
        assert!(out.contains("/tmp/x"), "細節不得被丟棄：{out}");
        assert!(!out.contains("{{"), "不得殘留佔位符：{out}");
    }

    /// en-US 訊息不得夾全角標點——**包含括號分支**。
    ///
    /// 原本括號寫死成「（）」（U+FF08/FF09，屬全角範圍）。既有的
    /// `cbom_error_detail_follows_request_language` 測的是 `target_not_archive`，
    /// 那個鍵有 `{{target}}` 故走插值分支、產不出括號，於是這條漏了一輪
    /// ——是 node 實測前端渲染時才看見 `Engine error（/path）`。
    #[test]
    fn english_messages_never_use_fullwidth_punctuation() {
        let c = Catalog::load("en-US");
        // 逐鍵掃，兩種分支都要走到
        for key in [
            "cbom.err.target_not_local",
            "cbom.err.target_unreadable",
            "cbom.err.target_not_archive",
            "cbom.err.timeout",
            "cbom.err.empty_output",
            "cbom.err.stdout_not_json",
            "cbom.err.not_cyclonedx",
            "cbom.err.engine",
        ] {
            let out = c.render_cbom(key, Some("/mnt/target/firmware.bin"));
            let bad: Vec<char> = out
                .chars()
                .filter(
                    |ch| matches!(*ch as u32, 0x4E00..=0x9FFF | 0x3000..=0x303F | 0xFF00..=0xFFEF),
                )
                .collect();
            assert!(
                bad.is_empty(),
                "{key} 的 en-US 訊息夾全角字元 {bad:?}：{out}"
            );
            assert!(
                out.contains("/mnt/target/firmware.bin"),
                "{key}: 細節消失：{out}"
            );
        }
        // zh-TW 反過來要用全角括號（否則中文訊息裡混半角括號）
        let zh = Catalog::load("zh-TW");
        let out = zh.render_cbom("cbom.err.engine", Some("/x"));
        assert!(
            out.contains('（') && out.contains('）'),
            "zh-TW 應用全角括號：{out}"
        );
    }

    #[test]
    fn render_cbom_uses_secs_for_timeout_and_target_otherwise() {
        for lang in ["zh-TW", "en-US"] {
            let c = Catalog::load(lang);
            let t = c.render_cbom("cbom.err.timeout", Some("600"));
            assert!(t.contains("600") && !t.contains("{{"), "{lang}: {t}");
            let a = c.render_cbom("cbom.err.target_not_archive", Some("/tmp/f.bin"));
            assert!(a.contains("/tmp/f.bin") && !a.contains("{{"), "{lang}: {a}");
            assert_eq!(a.matches("/tmp/f.bin").count(), 1, "路徑不得重複：{a}");
        }
    }

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
