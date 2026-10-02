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

#[test]
fn placeholder_extractor_sees_what_it_should() {
    assert_eq!(
        placeholders("{{a}} x {{b}}{{a}}"),
        ["a", "b"].iter().map(|s| s.to_string()).collect()
    );
    assert!(placeholders("沒有佔位符").is_empty());
}
