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

/// 支援的語系碼正規化：`en…` → `en-US`、`zh…` → `zh-TW`，其餘（含空字串）→ `None`。
///
/// CLI（`--lang`／`CYTRACE_LANG`）、[`Catalog::load`] 與 server 的 `Lang` 共用這一份規則；
/// 不支援時各自決定退回方式（CLI 印警告後用 zh-TW；API 協商依 ADR-011 §7 退回 zh-TW）。
/// 前綴判斷是既有行為（`--lang en`、`en_US.UTF-8` 一直可用）。T912 前 `Catalog::load` 與
/// server 的 `Lang::from_code` 各寫一份，T912 收成這一份（CLI 的 `resolve_lang` 也用它），不收緊。
pub fn lang_code(raw: &str) -> Option<&'static str> {
    let l = raw.trim().to_ascii_lowercase();
    if l.starts_with("en") {
        Some("en-US")
    } else if l.starts_with("zh") {
        Some("zh-TW")
    } else {
        None
    }
}

/// 預設語系（fallback）。
pub const DEFAULT_LANG: &str = "zh-TW";

/// 「純 i18n 鍵 + 不可翻譯參數」的錯誤：在**輸出的那一端**依語系渲染。
///
/// 產生錯誤的地方（設定解析、TLS 載入、讀寫檔）通常拿不到語系；把說明句寫死在那裡，
/// `--lang en-US` 下就會吐中文（T912 實測：serve 的 8 處設定錯誤、TLS、資料目錄全是如此）。
/// 參數只放路徑、環境變數名、使用者輸入值、系統錯誤訊息這類**不可翻譯的資料**。
///
/// `Display` 以預設語系渲染，只作沒有 downcast 時的最後防線；正常路徑由呼叫端以
/// [`Localized::render`] 依操作員語系渲染。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Localized {
    pub key: &'static str,
    pub vars: Vec<(&'static str, String)>,
}

impl Localized {
    pub fn new(key: &'static str) -> Self {
        Localized {
            key,
            vars: Vec::new(),
        }
    }

    /// 加一個插值參數（值為不可翻譯的資料）。
    pub fn var(mut self, name: &'static str, value: impl Into<String>) -> Self {
        self.vars.push((name, value.into()));
        self
    }

    pub fn render(&self, cat: &Catalog) -> String {
        let vars: Vec<(&str, &str)> = self.vars.iter().map(|(k, v)| (*k, v.as_str())).collect();
        cat.t(self.key, &vars)
    }
}

impl std::fmt::Display for Localized {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.render(&Catalog::load(DEFAULT_LANG)))
    }
}

impl std::error::Error for Localized {}

impl Catalog {
    /// 依語言碼載入（見 [`lang_code`]；不支援的值 → zh-TW）。fallback 永遠是 zh-TW。
    pub fn load(lang: &str) -> Self {
        let is_en = lang_code(lang) == Some("en-US");
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
    /// 細節的變數名**由 [`SECS_KEYS`] 明表決定**：表內的鍵其細節是秒數（`{{secs}}`），
    /// 其餘皆為目標路徑（`{{target}}`）。曾寫成「只有 `cbom.err.timeout`」的單一比較，
    /// 新增 `cbom.err.drain_timeout` 時因此漏掉（第九輪複審）。插值後若仍殘留佔位符、或細節根本沒被用上
    /// （鍵的文案未含該變數），才把細節補在括號內——否則會出現「佔位符原樣印出
    /// 且路徑重複一次」的畫面（第五輪修補造成、第六輪複審抓到的迴歸）。
    ///
    /// **CLI 與 server 共用本函式**：兩邊各寫一份渲染邏輯，就會有一邊先退化成裸鍵。
    pub fn render_cbom(&self, key: &str, detail: Option<&str>) -> String {
        // 未知鍵一律回退：`lookup` 全失敗時 `t()` 會回傳鍵本身，而該「原文」不含佔位符，
        // 於是走括號分支產出 `cbom.err.some_future_key（/path）`——**裸鍵印給使用者**。
        // 前端已如此回退（`frontend/src/cbom.ts`），兩側必須同規則
        // （第八輪複審 finding F：Rust 側漏了，且兩邊註解都聲稱「規則一致」）。
        let key = if lookup(&self.lang, key).is_some() || lookup(&self.fallback, key).is_some() {
            key
        } else {
            "cbom.err.engine"
        };
        let var = var_for_cbom_key(key);
        // **無細節時仍須插值**：`t(key, &[])` 對未填變數原樣保留，於是含 `{{target}}`
        // 的四個鍵會把佔位符印給使用者——第六輪已修過一次的畫面。
        // `reason_detail: None` 是實際可達狀態（序列化時可省略，舊報表重建時也會是 None），
        // 而 TS 側已插 `'?'`，Rust 側原本沒有（第八輪複審 finding E）。
        let Some(d) = detail else {
            let raw = lookup(&self.lang, key)
                .or_else(|| lookup(&self.fallback, key))
                .unwrap_or_else(|| key.to_string());
            return interpolate(&raw, &[(var, "?")]);
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

/// 鍵 → 細節的變數名。**明表，非「只有某一個鍵」的單一比較。**
///
/// 原本寫成 `key == "cbom.err.timeout"`。第八輪新增 `cbom.err.drain_timeout`
/// （文案用 `{{secs}}`）時它落到 else 拿到 `target`，於是插值不發生、`{{secs}}`
/// 原樣印給使用者——第六輪已修過一次的同一個畫面（第九輪複審）。
/// 以秒數為細節的鍵不只一個，故列表；`frontend/src/cbom.ts` 的 `SECS_KEYS` 是同一份，
/// 由 `every_message_uses_the_placeholder_its_rule_assigns` 與跨語言契約測試共同釘住。
pub const SECS_KEYS: &[&str] = &["cbom.err.timeout", "cbom.err.drain_timeout"];

pub fn var_for_cbom_key(key: &str) -> &'static str {
    if SECS_KEYS.contains(&key) {
        "secs"
    } else {
        "target"
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
///
/// **單次掃描模板，替換結果不再被掃描**。原實作依 `vars` 順序逐個 `replace`：
/// 前一個變數的值若含 `{{後一個變數}}`，會在下一輪被展開。T909 起 `with_message`
/// 第一次把**使用者輸入**接進插值（`fail_on` 的值），送 `{"fail_on":"{{allowed}}"}`
/// 就讓訊息變成「不合法的值是整串合法值」——使用者真正送的值從 message 消失
/// （T909 對抗式複審 v2，2/3 確認）。對舊實作會紅的是 `interpolation_does_not_re_expand_substituted_values`；
/// `interpolation_keeps_unknown_and_unclosed_placeholders` 釘的是新實作的邊界，舊實作本來就過。
/// i18next 前端預設 `skipOnVariables: true`，行為本就是單次。
///
/// 查不到的 `{{name}}` 原樣保留（`render_cbom` 等呼叫端靠殘留的 `{{` 偵測未插值）。
fn interpolate(template: &str, vars: &[(&str, &str)]) -> String {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(open) = rest.find("{{") {
        out.push_str(&rest[..open]);
        let after = &rest[open + 2..];
        match after.find("}}") {
            Some(close) => {
                let name = &after[..close];
                match vars.iter().find(|(k, _)| *k == name) {
                    Some((_, v)) => out.push_str(v),
                    None => {
                        out.push_str("{{");
                        out.push_str(name);
                        out.push_str("}}");
                    }
                }
                rest = &after[close + 2..];
            }
            None => {
                // 沒有收尾的 `{{`：原樣保留剩餘部分
                out.push_str(&rest[open..]);
                rest = "";
            }
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interpolation_does_not_re_expand_substituted_values() {
        // 使用者輸入恰好長得像另一個變數的佔位符時，不得被二次展開
        let out = interpolate(
            "bad: {{value}} (allowed: {{allowed}})",
            &[("value", "{{allowed}}"), ("allowed", "a / b")],
        );
        assert_eq!(out, "bad: {{allowed}} (allowed: a / b)", "值必須原樣插入");
        // 順序顛倒也一樣
        let out = interpolate("{{a}}{{b}}", &[("b", "{{a}}"), ("a", "X")]);
        assert_eq!(out, "X{{a}}");
    }

    #[test]
    fn interpolation_keeps_unknown_and_unclosed_placeholders() {
        assert_eq!(interpolate("x {{nope}} y", &[("a", "1")]), "x {{nope}} y");
        assert_eq!(interpolate("x {{a", &[("a", "1")]), "x {{a");
        assert_eq!(
            interpolate("{{a}}{{a}}", &[("a", "1")]),
            "11",
            "同一變數多處皆替換"
        );
        assert_eq!(interpolate("no vars", &[]), "no vars");
    }

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
