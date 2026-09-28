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
    ("cbom.err.drain_timeout", &[("secs", "5")]),
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
/// 本測試承接該風險的一半：任一側新增／刪除／改名 CBOM 錯誤鍵而另一側沒跟上，
/// 就在此轉紅。另一半由 `key_lists_are_derived_from_the_catalog_not_hand_copied`
/// 承接（它以 catalog 為事實源，涵蓋「兩側同時漏掉同一個鍵」這種本測試看不見的情形）。沿用 `cytrace-types` 序列化契約測試的手法（讀對側檔案比對），
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

/// 前端的 `SECS_KEYS` 明表必須與 Rust 的 [`cytrace_i18n::SECS_KEYS`] 逐項相同。
///
/// 規則漂開的後果不是崩潰而是**靜默**：變數名不符時 i18next 不插值，佔位符原樣印在
/// 報表上（第六輪修過一次、第八輪新增 `drain_timeout` 時又犯一次）。
/// 原本這支測試比對的是原始碼裡 `key === '…' ? 'secs'` 這個字串形狀，於是規則一改寫成
/// 明表它就紅——它釘的是**寫法**而非**內容**。改為比對清單本身。
#[test]
fn frontend_secs_key_table_matches_this_one() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../frontend/src/cbom.ts");
    let src = std::fs::read_to_string(path).expect("讀不到前端渲染實作");

    // 起點取 `= [` 之後：從 `SECS_KEYS: readonly string[] = [` 找起的話，
    // 型別註記裡的 `string[]` 那個 `]` 會先被命中，抽出空清單（本測試初版即如此，
    // 幸好 assert_eq 的 left 是 `[]` 當場現形）。
    let decl = src
        .find("SECS_KEYS")
        .expect("前端未定義 SECS_KEYS 明表——變數名規則可能又退回單一比較");
    let start = src[decl..]
        .find("= [")
        .map(|i| decl + i + 3)
        .expect("SECS_KEYS 宣告形式已變");
    let body = &src[start..];
    let end = body.find(']').expect("SECS_KEYS 陣列未閉合");
    let mut ts: Vec<String> = body[..end]
        .split('\'')
        .filter(|s| s.starts_with("cbom.err."))
        .map(|s| s.to_string())
        .collect();
    ts.sort();

    let mut rs: Vec<String> = cytrace_i18n::SECS_KEYS
        .iter()
        .map(|k| k.to_string())
        .collect();
    rs.sort();

    assert_eq!(
        ts, rs,
        "前端與 Rust 的「以秒數為細節」鍵表不一致。\n\
         不一致的那個鍵會拿到 target 而非 secs，於是插值不發生、\
         `{{{{secs}}}}` 原樣印在報表與 console 上。"
    );
    assert!(
        !rs.is_empty() && !ts.is_empty(),
        "任一側明表抽取為空——斷言在空轉"
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

// ── 鍵清單必須由 catalog 推導，不得手抄 ──

/// 三份 `cbom.err.*` 清單必須完全一致：catalog、本檔的 `CBOM_ERR_KEYS`、前端的 `CBOM_ERROR_KEYS`。
///
/// **手抄清單的漏法是靜默的。** 第八輪新增 `cbom.err.drain_timeout` 時只加進 locale，
/// 三份清單一份都沒加，於是（第九輪複審實測）：
/// - 前端的成員判定不中 → `renderCbomFailure` 回退 `cbom.err.engine` → 報表與 console
///   顯示「引擎錯誤 (5)」，「抽取逾時」這個成因**靜默消失**；
/// - 跨語言契約測試不紅，因為它比的是兩份手抄清單，而兩份都漏了同一個鍵；
/// - locale 裡那兩句新文案跟著產物出貨，卻永遠渲染不到。
///
/// 故清單的事實源是 **catalog**：新增鍵只要沒同步，這支測試就紅。
#[test]
fn key_lists_are_derived_from_the_catalog_not_hand_copied() {
    // catalog 的 cbom.err 命名空間全部葉鍵
    let zh: serde_json::Value = serde_json::from_str(include_str!("../../../locales/zh-TW.json"))
        .expect("zh-TW 應為合法 JSON");
    let mut catalog_keys: Vec<String> = zh
        .get("cbom")
        .and_then(|c| c.get("err"))
        .and_then(|e| e.as_object())
        .expect("catalog 應有 cbom.err 命名空間")
        .keys()
        .map(|k| format!("cbom.err.{k}"))
        .collect();
    catalog_keys.sort();

    let mut rust_keys: Vec<String> = CBOM_ERR_KEYS.iter().map(|(k, _)| k.to_string()).collect();
    rust_keys.sort();
    assert_eq!(
        rust_keys, catalog_keys,
        "CBOM_ERR_KEYS 與 catalog 的 cbom.err.* 不一致。\n\
         catalog 多出來的鍵不會被任何渲染測試涵蓋；少掉的鍵表示 locale 有死字串。"
    );

    // 前端清單
    let ts_path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../frontend/src/cbom.ts");
    let src = std::fs::read_to_string(ts_path).expect("讀不到前端渲染實作");
    let start = src
        .find("CBOM_ERROR_KEYS = [")
        .expect("前端未匯出 CBOM_ERROR_KEYS");
    let body = &src[start..];
    let end = body.find(']').expect("陣列未閉合");
    let mut ts_keys: Vec<String> = body[..end]
        .split('\'')
        .filter(|s| s.starts_with("cbom.err."))
        .map(|s| s.to_string())
        .collect();
    ts_keys.sort();
    ts_keys.dedup();
    assert_eq!(
        ts_keys, catalog_keys,
        "前端 CBOM_ERROR_KEYS 與 catalog 不一致。\n\
         少掉的鍵會被 renderCbomFailure 回退成泛用「引擎錯誤」，成因在報表上靜默消失。"
    );
}

/// 每個鍵的文案所用的佔位符，必須是規則指派給它的那一個；**且規則指派 `secs` 的鍵，
/// 其文案必須真的含 `{{secs}}`**（雙向）。
///
/// 規則的事實源是 [`cytrace_i18n::var_for_cbom_key`]（`SECS_KEYS` 明表）。新增
/// `cbom.err.drain_timeout` 時文案用了 `{{secs}}`，而當時的規則是「只有
/// `cbom.err.timeout` 用 secs」的單一比較，於是它拿到 `target` → 原文不含
/// `{{target}}` → 走括號分支 → **`{{secs}}` 原樣印給使用者**
/// （第九輪複審實測；第六輪已修過一次的同一個畫面，這次在 Rust 側）。
///
/// **反空轉**：`found` 為空時內層迴圈零斷言。9 鍵中有 4 鍵文案本就無佔位符，
/// 更要命的是若 `{{`/`}}` 語法哪天改變，抽取對所有鍵都落空、這支測試 100% 空轉而恆綠
/// （第十輪複審）。故在迴圈外斷言抽到的佔位符總數，並比對「應該有佔位符的鍵」數量。
#[test]
fn every_message_uses_the_placeholder_its_rule_assigns() {
    for (lang, raw) in [
        ("zh-TW", include_str!("../../../locales/zh-TW.json")),
        ("en-US", include_str!("../../../locales/en-US.json")),
    ] {
        let doc: serde_json::Value = serde_json::from_str(raw).expect("locale 應為合法 JSON");
        let errs = doc
            .get("cbom")
            .and_then(|c| c.get("err"))
            .and_then(|e| e.as_object())
            .expect("應有 cbom.err");
        let mut total_placeholders = 0usize;
        let mut secs_keys_seen = 0usize;
        for (short, val) in errs {
            let key = format!("cbom.err.{short}");
            let text = val.as_str().expect("文案應為字串");
            // 規則不在此重寫一份，直接問事實源（手抄就是下一個漂移點）
            let assigned = cytrace_i18n::var_for_cbom_key(&key);
            // 文案中實際出現的佔位符
            let found: Vec<&str> = text
                .split("{{")
                .skip(1)
                .filter_map(|s| s.split("}}").next())
                .collect();
            total_placeholders += found.len();
            for var in &found {
                assert_eq!(
                    *var, assigned,
                    "{lang} {key} 的文案用了 {{{{{var}}}}}，但規則指派給它的是 \
                     {{{{{assigned}}}}}——插值不會發生，佔位符會原樣印給使用者。\n\
                     文案：{text}"
                );
            }
            // 反方向：規則說這個鍵吃秒數，文案就必須真的留一個 {{secs}} 的位置，
            // 否則細節只能走括號分支，使用者看到的是「…（600）」而非「逾時 600 秒」。
            if assigned == "secs" {
                secs_keys_seen += 1;
                assert!(
                    found.contains(&"secs"),
                    "{lang} {key} 被規則指派 secs，但文案沒有 {{{{secs}}}} 的位置。\n\
                     文案：{text}"
                );
            }
        }
        // 反空轉：抽取失效時上面每一圈都是零斷言，整支測試恆綠
        assert!(
            total_placeholders >= 5,
            "{lang}：只抽到 {total_placeholders} 個佔位符——\
             `{{{{`/`}}}}` 語法或抽取邏輯可能已變，斷言在空轉"
        );
        assert_eq!(
            secs_keys_seen,
            cytrace_i18n::SECS_KEYS.len(),
            "{lang}：catalog 裡被指派 secs 的鍵有 {secs_keys_seen} 個，\
             但 SECS_KEYS 有 {} 個——兩者必須一一對應",
            cytrace_i18n::SECS_KEYS.len()
        );
    }
}
