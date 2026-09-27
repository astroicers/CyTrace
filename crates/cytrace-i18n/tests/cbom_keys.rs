//! CBOM 錯誤鍵的渲染契約（ADR-004 / ADR-013）。
//!
//! 第六輪複審實測：locale 字串帶 `{{target}}` / `{{secs}}` 佔位符，但呼叫端以
//! `t(key, &[])` 渲染，`interpolate` 對未填變數原樣保留 → 使用者看到
//! 「非 tar / gzip 封存檔，拒絕當成映像：{{target}}（/path/…）」。
//! 本檔釘住：每個鍵在**兩個語系**都存在，且渲染後不得殘留佔位符。

use cytrace_i18n::Catalog;

/// 所有 CBOM 錯誤鍵與其所需變數。
const CBOM_ERR_KEYS: &[(&str, &[(&str, &str)])] = &[
    ("cbom.err.target_not_local", &[("target", "/x")]),
    ("cbom.err.target_unreadable", &[("target", "/x")]),
    ("cbom.err.target_not_archive", &[("target", "/x")]),
    ("cbom.err.timeout", &[("secs", "600")]),
    ("cbom.err.empty_output", &[]),
    ("cbom.err.stdout_not_json", &[]),
    ("cbom.err.not_cyclonedx", &[]),
    ("cbom.err.engine", &[]),
];

#[test]
fn every_cbom_error_key_exists_in_both_locales() {
    for lang in ["zh-TW", "en-US"] {
        let cat = Catalog::load(lang);
        for (key, _) in CBOM_ERR_KEYS {
            assert_ne!(
                cat.t(key, &[]),
                *key,
                "{lang} 缺鍵 {key}（t() 回傳鍵本身即代表查不到）"
            );
        }
    }
}

#[test]
fn rendered_messages_leave_no_placeholder() {
    for lang in ["zh-TW", "en-US"] {
        let cat = Catalog::load(lang);
        for (key, vars) in CBOM_ERR_KEYS {
            let out = cat.t(key, vars);
            assert!(
                !out.contains("{{"),
                "{lang} 的 {key} 渲染後殘留佔位符：{out}"
            );
        }
    }
}

#[test]
fn keys_requiring_vars_actually_use_them() {
    // 反向保護：若 locale 字串未來拿掉佔位符，上面那條測試會恆真而失去意義。
    // 這條確認「需要變數的鍵」真的把值插進去了。
    let cat = Catalog::load("zh-TW");
    assert!(
        cat.t("cbom.err.target_not_archive", &[("target", "SENTINEL")])
            .contains("SENTINEL"),
        "target 變數須被插值"
    );
    assert!(
        cat.t("cbom.err.timeout", &[("secs", "42")]).contains("42"),
        "secs 變數須被插值"
    );
}
