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

// ── 跨語言契約：前端的第二份渲染實作不得與此處漂開 ──

/// 報表是單檔 HTML 且有執行期語言切換器，故成因必須在前端依當前語系渲染
/// （在 Rust 端預渲染成固定字串的話，切語言時訊息不會跟著變）。這使
/// `frontend/src/cbom.ts` 成為 `Catalog::render_cbom` 的第二份實作——
/// 「兩邊各寫一份，就會有一邊先退化」正是第六輪 finding A/B/C 的成因。
///
/// 本測試是承接那個風險的唯一機制：任一側新增／刪除／改名 CBOM 錯誤鍵而另一側
/// 沒跟上，就在此轉紅。沿用 `cytrace-types` 序列化契約測試的手法（讀對側檔案比對），
/// 因為前端無測試框架，而為此引入 vitest 會多一個要離線建置與審授權的依賴。
#[test]
fn frontend_cbom_key_list_matches_this_one() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../frontend/src/cbom.ts");
    let src =
        std::fs::read_to_string(path).unwrap_or_else(|e| panic!("讀不到前端渲染實作 {path}：{e}"));

    // 抽 CBOM_ERROR_KEYS 陣列裡的字面鍵
    let start = src
        .find("CBOM_ERROR_KEYS = [")
        .expect("前端未匯出 CBOM_ERROR_KEYS——契約已斷，報表可能印出裸鍵");
    let body = &src[start..];
    let end = body.find(']').expect("CBOM_ERROR_KEYS 陣列未閉合");
    let mut ts_keys: Vec<String> = body[..end]
        .split('\'')
        .filter(|s| s.starts_with("cbom.err."))
        .map(|s| s.to_string())
        .collect();
    ts_keys.sort();
    ts_keys.dedup();

    let mut rust_keys: Vec<String> = CBOM_ERR_KEYS.iter().map(|(k, _)| k.to_string()).collect();
    rust_keys.sort();

    assert_eq!(
        ts_keys,
        rust_keys,
        "前端與 Rust 的 CBOM 錯誤鍵清單不一致。\n\
         後果：多出來的鍵在報表上會渲染成裸鍵字串給交件對象看；\n\
         少掉的鍵會被前端回退成泛用「引擎錯誤」，成因靜默消失。\n\
         前端 {} 鍵 / Rust {} 鍵",
        ts_keys.len(),
        rust_keys.len()
    );
    assert!(
        !ts_keys.is_empty(),
        "抽取為空——正則或檔案形式已變，斷言在空轉"
    );
}

/// 前端的變數名規則必須與此處一致：逾時是 `secs`，其餘皆 `target`。
///
/// 規則漂開的後果不是崩潰而是**靜默**：變數名不符時 i18next 不插值，
/// 佔位符原樣印在報表上（第六輪那個已修過一次的畫面）。
#[test]
fn frontend_var_name_rule_matches_this_one() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../frontend/src/cbom.ts");
    let src = std::fs::read_to_string(path).expect("讀不到前端渲染實作");

    // Rust 側：哪些鍵需要 secs、哪些需要 target
    for (key, vars) in CBOM_ERR_KEYS {
        let expected = match vars.first() {
            Some(("secs", _)) => Some("secs"),
            Some(("target", _)) => Some("target"),
            _ => None,
        };
        if expected == Some("secs") {
            assert!(
                src.contains(&format!("key === '{key}' ? 'secs'")),
                "前端未把 {key} 對到 secs——佔位符會原樣印在報表上"
            );
        }
    }
    // 其餘一律 target（前端以三元運算的 else 分支承接）
    assert!(
        src.contains("'secs' : 'target'"),
        "前端的預設變數名不是 target——非逾時類的細節會插不進去"
    );
}

// ── 兩側行為契約：不只鍵與規則，邊界也要同 ──

/// `detail = None` 時不得印出佔位符（第八輪複審 finding E）。
///
/// `reason_detail` 是 `Option` 且序列化時可省略（golden JSON 就沒有該欄位），
/// 故 `cytrace report` 讀回舊版／被裁剪的 `scan-result.json` 時必然走到這條路。
/// 契約測試比對鍵清單與變數名規則，**不碰行為**，所以這條在 TS 修好之後
/// Rust 側還漏了一輪。
#[test]
fn none_detail_never_leaks_placeholders() {
    for lang in ["zh-TW", "en-US"] {
        let cat = Catalog::load(lang);
        for (key, _) in CBOM_ERR_KEYS {
            let out = cat.render_cbom(key, None);
            assert!(
                !out.contains("{{"),
                "{lang} {key}: detail=None 時殘留佔位符：{out}"
            );
            assert_ne!(out.trim(), *key, "{lang} {key}: 渲染出裸鍵");
        }
    }
}

/// 未知鍵一律回退 `cbom.err.engine`，兩側同規則（第八輪複審 finding F）。
#[test]
fn unknown_keys_fall_back_instead_of_printing_the_raw_key() {
    for lang in ["zh-TW", "en-US"] {
        let cat = Catalog::load(lang);
        for detail in [Some("/mnt/target/x.bin"), None] {
            let out = cat.render_cbom("cbom.err.some_new_key_from_the_future", detail);
            assert!(
                !out.contains("cbom.err."),
                "{lang}: 未知鍵不得印出裸鍵（報表會把它顯示給交件對象看）：{out}"
            );
            assert!(!out.contains("{{"), "{lang}: 不得殘留佔位符：{out}");
            if let Some(d) = detail {
                assert!(out.contains(d), "{lang}: 回退時細節不得消失：{out}");
            }
        }
        // 完全空的鍵名同樣不得漏出
        let out = cat.render_cbom("", Some("/x"));
        assert!(!out.is_empty() && !out.contains("{{"), "空鍵名：{out}");
    }
}
