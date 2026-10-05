//! 兩語系的每一個鍵，`{{var}}` 佔位符集合必須相同（ADR-004 共用值契約）。
//!
//! 之前只有 `cbom.err.*` 有這道檢查（cbom_keys.rs）；`cli.*`／`server.*` 新增鍵時，若一邊漏了
//! 佔位符，插值後那一語就少了路徑或使用者輸入值，而沒有任何檢查會擋（T912 盤點）。

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

fn leaves(v: &Value, prefix: &str, out: &mut BTreeMap<String, String>) {
    match v {
        Value::Object(m) => {
            for (k, child) in m {
                let p = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                leaves(child, &p, out);
            }
        }
        Value::String(s) => {
            out.insert(prefix.to_string(), s.clone());
        }
        _ => {}
    }
}

fn placeholders(s: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut rest = s;
    while let Some(i) = rest.find("{{") {
        let after = &rest[i + 2..];
        let Some(j) = after.find("}}") else { break };
        out.insert(after[..j].to_string());
        rest = &after[j + 2..];
    }
    out
}

fn load(name: &str) -> BTreeMap<String, String> {
    let path = format!("{}/../../locales/{name}.json", env!("CARGO_MANIFEST_DIR"));
    let v: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let mut out = BTreeMap::new();
    leaves(&v, "", &mut out);
    out
}

#[test]
fn every_key_has_the_same_placeholders_in_both_languages() {
    let zh = load("zh-TW");
    let en = load("en-US");
    assert!(zh.len() >= 150, "只讀到 {} 個鍵——載入可能失效", zh.len());
    let mut diffs = Vec::new();
    for (k, z) in &zh {
        let Some(e) = en.get(k) else { continue }; // 缺鍵由 scripts/i18n-check.py 把關
        let (pz, pe) = (placeholders(z), placeholders(e));
        if pz != pe {
            diffs.push(format!("{k}: zh-TW {pz:?} ≠ en-US {pe:?}"));
        }
    }
    assert!(diffs.is_empty(), "佔位符不一致：\n{}", diffs.join("\n"));
}

/// 佔位符名稱必須是單純的識別字，不得含空白。
///
/// Rust 的 `interpolate` 以名稱**全文**比對變數、不去頭尾空白；react-i18next 則會 trim。
/// 同一份 locale 若寫成 `{{ addr }}`，console 與報表正常顯示，CLI／server 卻原樣印出
/// `{{ addr }}`——而兩語佔位符集合一致、程式碼變數也對得上（若比對時 trim），沒有任何閘會紅
/// （T912 複審 newgates#2 實測）。故在 locale 端直接禁止這種寫法。
#[test]
fn placeholder_names_are_plain_identifiers() {
    let ok = |n: &str| {
        let mut cs = n.chars();
        cs.next().is_some_and(|c| c.is_ascii_alphabetic())
            && cs.all(|c| c.is_ascii_alphanumeric() || c == '_')
    };
    let mut bad = Vec::new();
    for lang in ["zh-TW", "en-US"] {
        for (k, v) in load(lang) {
            for n in placeholders(&v) {
                if !ok(&n) {
                    bad.push(format!("{lang} {k}: {{{{{n}}}}}"));
                }
            }
        }
    }
    assert!(
        bad.is_empty(),
        "佔位符名稱不是單純識別字：\n{}",
        bad.join("\n")
    );
    assert!(!ok(" addr ") && !ok("addr ") && !ok("") && ok("addr") && ok("max_mb"));
}

#[test]
fn placeholder_extractor_sees_what_it_should() {
    assert_eq!(
        placeholders("{{a}} x {{b}}{{a}}"),
        ["a", "b"].iter().map(|s| s.to_string()).collect()
    );
    assert!(placeholders("沒有佔位符").is_empty());
}
