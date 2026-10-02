//! i18n 棘輪：所有 crate 的生產碼不得有中文字面值，只有 [`EXEMPT`] 明列的例外（NFR-06 / T909 / T912）。
//!
//! T909 把流進 **API 回應**的中文散文全數改走 i18n 鍵（經 53 個代理分類 + 反證確認範圍）；
//! T912 把印在**操作者終端**的（serve 啟動錯誤、job 隔離與落盤警告、CLI 錯誤）也改走鍵，
//! 並把掃描範圍從 server 擴到全部 crate——cli 與 core 一樣會把字串印給操作者。
//!
//! 本測試是雙向的：
//! - 出現清單外的中文字面值 → 紅（使用者可見字串必須走 i18n 鍵）
//! - 清單內的項目次數不符 → 紅（多了＝複製了例外字串；少了＝修掉後沒更新清單，
//!   日後有人照同樣字串加回來也不會被抓）
//!
//! 鍵為（crate 相對路徑, 字面值全文），不用行號——行號一改就漂。

use std::path::Path;

/// 明列的例外：（crate 相對路徑, 字面值**全文**, 出現次數, 理由）。
///
/// 比對全文而不是片段：片段比對下，一筆 `"（"` 會豁免該檔所有含全形括號的字面值。
/// 計次數：只看存在的話，一筆清單能豁免任意多個同字串字面值——複製既有訊息正是新散文
/// 最常見的來源（T909 對抗式複審 v11，3/3 確認）。
const EXEMPT: &[(&str, &str, usize, &str)] = &[
    (
        "cytrace-core/src/engine.rs",
        "reap 只在 early return 時取走",
        1,
        "unreachable! 的不變式說明；panic 訊息給開發者，依構造到不了",
    ),
    (
        "cytrace-core/src/engine.rs",
        "正常結束路徑上 reap 必然還在",
        1,
        "expect 的不變式說明；同上",
    ),
    (
        "cytrace-i18n/src/lib.rs",
        "內嵌 locale 應為合法 JSON",
        1,
        "expect：locale 以 include_str! 內嵌，壞掉在測試就紅，執行期到不了",
    ),
    (
        "cytrace-i18n/src/lib.rs",
        "內嵌 zh-TW 應為合法 JSON",
        1,
        "同上",
    ),
    (
        "cytrace-i18n/src/lib.rs",
        "（",
        1,
        "Catalog::parens 的 zh-TW 分支（依語系選全形／半形括號，en-US 走半形）",
    ),
    ("cytrace-i18n/src/lib.rs", "）", 1, "同上"),
];

/// 與 tests/jobs.rs 的 `has_cjk` 同範圍：漢字 + CJK 標點 + 全形字元。
/// 初版只認漢字，只含全形標點的字面值（`"CYTRACE_SCAN_ROOTS：{e}"`）完全看不到。
fn is_cjk(c: char) -> bool {
    matches!(c as u32, 0x4E00..=0x9FFF | 0x3000..=0x303F | 0xFF00..=0xFFEF)
}

/// 一個檔案中「生產碼」的 CJK 字串字面值（以 `syn` 解析 AST）。
///
/// 跳過 `#[cfg(test)]` 修飾的節點（項目、impl／trait 成員、match arm、欄位、variant、
/// let、帶屬性的運算式）；doc 註解不算；巨集與非 doc 屬性裡的字串照算。
///
/// 歷程：前三版都是手寫的逐行掃描器。初版遇到第一個 `#[cfg(test)]` 就停（第二輪 tests#4）；
/// 第二版只在下一行是 `mod` 時停，`mod x;` 與中段 inline 模組照樣藏住其後的生產碼（第三輪
/// server#4）；第三版改成括號配對跳過項目，卻被 match arm 上的 cfg(test)、raw string、
/// 跨行字串、`/* { */` 區塊註解一路吃掉其後的生產碼（第四輪 server#3）。syn 自己處理這些語法。
fn production_cjk_literals(text: &str) -> Vec<String> {
    let file = syn::parse_file(text).expect("棘輪解析 Rust 原始碼失敗");
    let mut c = Collector::default();
    c.visit_file(&file);
    c.out
        .into_iter()
        .filter(|s| s.chars().any(is_cjk))
        .collect()
}

use syn::visit::{self, Visit};

#[derive(Default)]
struct Collector {
    out: Vec<String>,
}

fn is_cfg_test(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|a| {
        a.path().is_ident("cfg")
            && a.meta
                .require_list()
                .is_ok_and(|l| l.tokens.to_string().trim() == "test")
    })
}

impl Collector {
    /// token 串裡的字串字面值（巨集參數、屬性參數；含 raw string 與跳脫序列）。
    fn tokens(&mut self, ts: proc_macro2::TokenStream) {
        for tt in ts {
            match tt {
                proc_macro2::TokenTree::Group(g) => self.tokens(g.stream()),
                proc_macro2::TokenTree::Literal(l) => {
                    if let Ok(s) = syn::parse_str::<syn::LitStr>(&l.to_string()) {
                        self.out.push(s.value());
                    }
                }
                _ => {}
            }
        }
    }
}

macro_rules! skip_cfg_test {
    ($self:ident, $node:ident, $attrs:expr, $walk:path) => {
        if !is_cfg_test($attrs) {
            $walk($self, $node);
        }
    };
}

impl<'ast> Visit<'ast> for Collector {
    fn visit_lit_str(&mut self, l: &'ast syn::LitStr) {
        self.out.push(l.value());
    }
    fn visit_macro(&mut self, m: &'ast syn::Macro) {
        self.tokens(m.tokens.clone());
    }
    fn visit_attribute(&mut self, a: &'ast syn::Attribute) {
        // doc 註解不是使用者可見字串；其他屬性（如 #[error("…")]）照算
        if !a.path().is_ident("doc") {
            if let syn::Meta::List(l) = &a.meta {
                self.tokens(l.tokens.clone());
            } else if let syn::Meta::NameValue(nv) = &a.meta {
                self.visit_expr(&nv.value);
            }
        }
    }
    fn visit_item(&mut self, i: &'ast syn::Item) {
        use syn::Item::*;
        let attrs: &[syn::Attribute] = match i {
            Const(x) => &x.attrs,
            Enum(x) => &x.attrs,
            ExternCrate(x) => &x.attrs,
            Fn(x) => &x.attrs,
            ForeignMod(x) => &x.attrs,
            Impl(x) => &x.attrs,
            Macro(x) => &x.attrs,
            Mod(x) => &x.attrs,
            Static(x) => &x.attrs,
            Struct(x) => &x.attrs,
            Trait(x) => &x.attrs,
            TraitAlias(x) => &x.attrs,
            Type(x) => &x.attrs,
            Union(x) => &x.attrs,
            Use(x) => &x.attrs,
            _ => &[],
        };
        skip_cfg_test!(self, i, attrs, visit::visit_item);
    }
    fn visit_impl_item(&mut self, i: &'ast syn::ImplItem) {
        use syn::ImplItem::*;
        let attrs: &[syn::Attribute] = match i {
            Const(x) => &x.attrs,
            Fn(x) => &x.attrs,
            Type(x) => &x.attrs,
            Macro(x) => &x.attrs,
            _ => &[],
        };
        skip_cfg_test!(self, i, attrs, visit::visit_impl_item);
    }
    fn visit_trait_item(&mut self, i: &'ast syn::TraitItem) {
        use syn::TraitItem::*;
        let attrs: &[syn::Attribute] = match i {
            Const(x) => &x.attrs,
            Fn(x) => &x.attrs,
            Type(x) => &x.attrs,
            Macro(x) => &x.attrs,
            _ => &[],
        };
        skip_cfg_test!(self, i, attrs, visit::visit_trait_item);
    }
    fn visit_arm(&mut self, a: &'ast syn::Arm) {
        skip_cfg_test!(self, a, &a.attrs, visit::visit_arm);
    }
    fn visit_field(&mut self, f: &'ast syn::Field) {
        skip_cfg_test!(self, f, &f.attrs, visit::visit_field);
    }
    fn visit_variant(&mut self, v: &'ast syn::Variant) {
        skip_cfg_test!(self, v, &v.attrs, visit::visit_variant);
    }
    fn visit_field_value(&mut self, f: &'ast syn::FieldValue) {
        skip_cfg_test!(self, f, &f.attrs, visit::visit_field_value);
    }
    fn visit_local(&mut self, l: &'ast syn::Local) {
        skip_cfg_test!(self, l, &l.attrs, visit::visit_local);
    }
    fn visit_stmt_macro(&mut self, m: &'ast syn::StmtMacro) {
        skip_cfg_test!(self, m, &m.attrs, visit::visit_stmt_macro);
    }
    fn visit_expr(&mut self, e: &'ast syn::Expr) {
        // 帶 #[cfg(test)] 的運算式（多半是陳述式）：常見變體逐一檢查屬性
        use syn::Expr::*;
        let attrs: &[syn::Attribute] = match e {
            Assign(x) => &x.attrs,
            Block(x) => &x.attrs,
            Call(x) => &x.attrs,
            If(x) => &x.attrs,
            Macro(x) => &x.attrs,
            Match(x) => &x.attrs,
            MethodCall(x) => &x.attrs,
            Return(x) => &x.attrs,
            Struct(x) => &x.attrs,
            Unsafe(x) => &x.attrs,
            _ => &[],
        };
        skip_cfg_test!(self, e, attrs, visit::visit_expr);
    }
}

/// 抽取器的正負對照：反空轉只驗「抽到東西」不夠，要驗「抓得到違規」。
/// 前 8 組是歷輪複審實際找到、前一版掃描器會吃掉其後生產碼的形狀（第二輪 1 組、第三輪 2 組、
/// 第四輪 5 組）；最後 2 組（doc 註解與屬性、cfg(test) 的 let／陳述式）是釘住 syn 版語意的設計
/// 案例，不是歷輪找到的（宣稱核對 server#2／meta#3 更正前版「每組都是」的說法）。
#[test]
fn extractor_sees_past_test_only_items() {
    let cases: &[(&str, &str, &[&str])] = &[
        (
            "test-only 輔助函式與檔尾測試模組",
            "const A: &str = \"甲\";\n#[cfg(test)]\nfn helper() -> &'static str { \"己\" }\nfn f() -> &'static str { \"乙\" }\n// \"註解裡的丙\"\n#[cfg(test)]\n#[allow(dead_code)]\nmod tests {\n    const T: &str = \"測試裡的丁\";\n}\n",
            &["甲", "乙"],
        ),
        (
            "外部檔模組宣告（第三輪 server#4）",
            "#[cfg(test)]\nmod helpers;\nfn f() -> &'static str { \"乙\" }\n",
            &["乙"],
        ),
        (
            "中段 inline 測試模組，內含右括號字串與字元",
            "#[cfg(test)]\nmod t {\n    const S: &str = \"}\";\n    const U: &str = \"辛\";\n    fn g() { let _ = '{'; }\n}\nfn k() -> &'static str { \"壬\" }\n",
            &["壬"],
        ),
        (
            "match arm 上的 cfg(test)（第四輪 server#3）",
            "fn f(x: u8) -> &'static str {\n    match x {\n        #[cfg(test)]\n        0 => \"測\",\n        1 => { \"丙\" }\n        _ => \"丁\",\n    }\n}\n",
            &["丙", "丁"],
        ),
        (
            "struct 欄位上的 cfg(test)",
            "struct S {\n    #[cfg(test)]\n    x: u8,\n}\nconst MSG: &str = \"生產丁\";\n",
            &["生產丁"],
        ),
        (
            "測試模組裡的 raw string 含大括號與引號",
            "#[cfg(test)]\nmod t {\n    const J: &str = r#\"{\"m\":\"a{b\"}\"#;\n}\nfn a() -> &'static str { \"戊\" }\nfn b() -> &'static str { \"庚\" }\n",
            &["戊", "庚"],
        ),
        (
            "cfg(test) 項目內的跨行字串、續行以大括號開頭（第四輪 server#3 的實際形狀）",
            "#[cfg(test)]\nmod t {\n    const S: &str = \"第一行\n{ 第二行\";\n}\nfn g() -> &'static str { \"辛\" }\n",
            &["辛"],
        ),
        (
            "測試模組裡的區塊註解含大括號、raw string 結尾反斜線",
            "#[cfg(test)]\nmod t {\n    /* { */\n    const R: &str = r\"\\\";\n}\nfn h() -> &'static str { \"癸\" }\n",
            &["癸"],
        ),
        (
            "doc 註解不算；巨集與非 doc 屬性照算",
            "/// 文件說明\n#[doc = \"也是文件\"]\n#[serde(rename = \"屬性裡的名稱\")]\nstruct S;\nfn f(k: &str) -> String { format!(\"{k} 格式字串\") }\n",
            &["屬性裡的名稱", "{k} 格式字串"],
        ),
        (
            "cfg(test) 的 let 與陳述式",
            "fn f() {\n    #[cfg(test)]\n    let _a = \"測一\";\n    #[cfg(test)]\n    println!(\"測二\");\n    eprintln!(\"生產\");\n}\n",
            &["生產"],
        ),
    ];
    for (name, src, want) in cases {
        assert_eq!(production_cjk_literals(src), *want, "{name}：\n{src}");
    }
}

fn walk(dir: &Path, files: &mut Vec<std::path::PathBuf>) {
    for e in std::fs::read_dir(dir).expect("讀 src") {
        let p = e.unwrap().path();
        if p.is_dir() {
            walk(&p, files);
        } else if p.extension().and_then(|x| x.to_str()) == Some("rs") {
            files.push(p);
        }
    }
}

#[test]
fn cjk_literals_only_in_exempt_places() {
    // 掃全部 crate 的 src：cli 與 core 也印操作者終端訊息（T912 前只掃 server，
    // cli 與 core 修好後沒有任何機械閘防回歸）
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut files = Vec::new();
    let mut scanned = Vec::new();
    for e in std::fs::read_dir(&crates).expect("讀 crates/") {
        let dir = e.unwrap().path();
        let src = dir.join("src");
        if src.is_dir() {
            scanned.push(dir.file_name().unwrap().to_string_lossy().into_owned());
            walk(&src, &mut files);
        }
    }
    // 反空轉：目錄結構一改，掃描範圍可能悄悄縮成零
    for must in [
        "cytrace-server",
        "cytrace-cli",
        "cytrace-core",
        "cytrace-i18n",
    ] {
        assert!(
            scanned.iter().any(|c| c == must),
            "沒掃到 {must}——掃描範圍可能已失效（掃到：{scanned:?}）"
        );
    }
    assert!(
        files.len() >= 30,
        "只找到 {} 個 .rs——掃描可能已失效",
        files.len()
    );

    let mut found: Vec<(String, String)> = Vec::new();
    for f in &files {
        let rel = f
            .strip_prefix(&crates)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        let text = std::fs::read_to_string(f).unwrap();
        for lit in production_cjk_literals(&text) {
            found.push((rel.clone(), lit));
        }
    }

    // 方向 1：清單外的中文字面值
    let unexpected: Vec<_> = found
        .iter()
        .filter(|(file, lit)| !EXEMPT.iter().any(|(ef, el, _, _)| file == ef && lit == el))
        .collect();
    assert!(
        unexpected.is_empty(),
        "出現清單外的中文字面值（使用者可見字串須走 i18n 鍵；確屬開發者訊息者，\
         加進 EXEMPT 並寫明理由）：\n{}",
        unexpected
            .iter()
            .map(|(f, l)| format!("  {f}: \"{l}\""))
            .collect::<Vec<_>>()
            .join("\n")
    );

    // 方向 2：次數必須精確相符
    let drift: Vec<_> = EXEMPT
        .iter()
        .filter_map(|(ef, el, want, _)| {
            let got = found.iter().filter(|(f, l)| f == ef && l == el).count();
            (got != *want).then(|| format!("  {ef} 「{el}」：清單記 {want} 處，實際 {got} 處"))
        })
        .collect();
    assert!(
        drift.is_empty(),
        "EXEMPT 與程式碼次數不符（多了＝複製了例外字串；少了＝修掉後請更新清單）：\n{}",
        drift.join("\n")
    );
}
