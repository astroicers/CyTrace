//! 程式碼端的插值變數必須與 catalog 佔位符相同（T912 複審 gates#7／server#0）。
//!
//! `Catalog::t` 對缺的變數保留 `{{name}}` 原樣、對多給的變數默默忽略——兩種錯都不會讓
//! 其他測試轉紅，操作者只會看到「quarantined to {{to}}」，路徑整段消失。複審實測：把
//! `.var("to", …)` 改成 `.var("dest", …)`、或整個拿掉，全套測試仍綠。
//! `cytrace-i18n/tests/placeholders.rs` 只比兩個語系彼此；本檔比「程式碼 vs catalog」。
//!
//! 以 syn 解析，比得了的呼叫形狀（鍵與變數名都必須是字面值）：
//! - `Localized::new("k").var("a", …).var("b", …)`——整條鏈；
//! - `<任何接收者>.t("k", &[("a", …), …])` 與 `.with_message("k", &[…])`，含格式巨集參數內；
//! - 包一層的輔助函式：函式本體以**參數**當鍵建 `Localized`（如 CLI 的 `path_err`），
//!   其呼叫點 `path_err("k", …)` 以該函式本體的變數集合比對。
//!
//! 比不了而略過的：鍵不是字面值、變數清單不是字面值陣列（`&vars`）——數量列在失敗訊息。
//! 不在 catalog 的鍵交給 `scripts/i18n-check.py`。測試碼也一起比：以真鍵配錯變數同樣是錯。

mod common;

use std::collections::{BTreeMap, BTreeSet};
use syn::punctuated::Punctuated;
use syn::visit::{self, Visit};
use syn::{Expr, Lit};

/// 刻意不插值的呼叫：（檔案, 鍵, 理由）。每筆都必須真的命中，否則轉紅（防清單陳舊）。
const INTENTIONAL: &[(&str, &str, &str)] = &[(
    "crates/cytrace-i18n/src/lib.rs",
    "cbom.err.target_not_archive",
    "測試取未插值的原文前兩字，用來構造「細節恰為譯文子字串」的邊界輸入",
)];

fn placeholders(s: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut rest = s;
    while let Some(i) = rest.find("{{") {
        let after = &rest[i + 2..];
        let Some(j) = after.find("}}") else { break };
        out.insert(after[..j].trim().to_string());
        rest = &after[j + 2..];
    }
    out
}

/// 鍵 → 該語系的佔位符集合。
fn catalog(lang: &str) -> BTreeMap<String, BTreeSet<String>> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../locales")
        .join(format!("{lang}.json"));
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).expect("讀 locale"))
            .expect("locale JSON");
    let mut out = BTreeMap::new();
    fn leaves(v: &serde_json::Value, prefix: &str, out: &mut BTreeMap<String, BTreeSet<String>>) {
        match v {
            serde_json::Value::Object(m) => {
                for (k, c) in m {
                    let p = if prefix.is_empty() {
                        k.clone()
                    } else {
                        format!("{prefix}.{k}")
                    };
                    leaves(c, &p, out);
                }
            }
            serde_json::Value::String(s) => {
                out.insert(prefix.to_string(), placeholders(s));
            }
            _ => {}
        }
    }
    leaves(&v, "", &mut out);
    out
}

#[derive(Debug, Clone, PartialEq)]
enum Vars {
    Known(BTreeSet<String>),
    /// 變數名不是字面值（比不了）。
    Dynamic,
}

#[derive(Debug)]
struct Site {
    file: String,
    shape: &'static str,
    key: String,
    vars: Vars,
}

#[derive(Default)]
struct Finder {
    file: String,
    fn_stack: Vec<String>,
    sites: Vec<Site>,
    /// 以參數當鍵建 `Localized` 的函式 → 它補上的變數。
    helpers: BTreeMap<String, BTreeSet<String>>,
    /// 單一識別字函式、第一個引數是字串字面值的呼叫：（檔案, 函式名, 鍵）。
    calls: Vec<(String, String, String)>,
    /// 鍵是字面值、但變數清單比不了的呼叫數。
    skipped_dynamic: usize,
}

fn lit_str(e: &Expr) -> Option<String> {
    match e {
        Expr::Lit(l) => match &l.lit {
            Lit::Str(s) => Some(s.value()),
            _ => None,
        },
        Expr::Paren(p) => lit_str(&p.expr),
        _ => None,
    }
}

/// `&[("a", x), ("b", y)]` → {a, b}；不是這個形狀 → None。
fn var_array(e: &Expr) -> Option<BTreeSet<String>> {
    let e = match e {
        Expr::Reference(r) => &*r.expr,
        other => other,
    };
    let Expr::Array(a) = e else { return None };
    let mut set = BTreeSet::new();
    for el in &a.elems {
        let Expr::Tuple(t) = el else { return None };
        set.insert(lit_str(t.elems.first()?)?);
    }
    Some(set)
}

fn is_localized_new(func: &Expr) -> bool {
    let Expr::Path(p) = func else { return false };
    let segs: Vec<String> = p
        .path
        .segments
        .iter()
        .map(|s| s.ident.to_string())
        .collect();
    segs.len() >= 2 && segs[segs.len() - 2] == "Localized" && segs[segs.len() - 1] == "new"
}

impl Finder {
    fn site(&mut self, shape: &'static str, key: String, vars: Vars) {
        if vars == Vars::Dynamic {
            self.skipped_dynamic += 1;
        }
        self.sites.push(Site {
            file: self.file.clone(),
            shape,
            key,
            vars,
        });
    }

    /// `Localized::new(k)` 起頭、接零或多個 `.var(name, v)` 的鏈。不是這種鏈 → false。
    fn localized_chain(&mut self, e: &Expr) -> bool {
        let mut names = BTreeSet::new();
        let mut dynamic = false;
        let mut values = Vec::new();
        let mut cur = e;
        while let Expr::MethodCall(mc) = cur {
            if mc.method != "var" || mc.args.len() != 2 {
                return false;
            }
            match lit_str(&mc.args[0]) {
                Some(n) => {
                    names.insert(n);
                }
                None => dynamic = true,
            }
            values.push(&mc.args[1]);
            cur = &mc.receiver;
        }
        let Expr::Call(c) = cur else { return false };
        if !is_localized_new(&c.func) || c.args.len() != 1 {
            return false;
        }
        let vars = if dynamic {
            Vars::Dynamic
        } else {
            Vars::Known(names.clone())
        };
        match lit_str(&c.args[0]) {
            Some(key) => self.site("Localized", key, vars),
            None => {
                // 鍵來自參數：記為輔助函式，呼叫點另行比對
                if let (Some(f), false) = (self.fn_stack.last().cloned(), dynamic) {
                    self.helpers.insert(f, names);
                }
            }
        }
        for v in values {
            self.visit_expr(v);
        }
        for a in &c.args {
            self.visit_expr(a);
        }
        true
    }
}

impl<'ast> Visit<'ast> for Finder {
    fn visit_item_fn(&mut self, f: &'ast syn::ItemFn) {
        self.fn_stack.push(f.sig.ident.to_string());
        visit::visit_item_fn(self, f);
        self.fn_stack.pop();
    }
    fn visit_impl_item_fn(&mut self, f: &'ast syn::ImplItemFn) {
        self.fn_stack.push(f.sig.ident.to_string());
        visit::visit_impl_item_fn(self, f);
        self.fn_stack.pop();
    }
    /// 格式巨集（`eprintln!("{}", cat.t(…))`）的參數 syn 不會自動解析；能解成逗號分隔的
    /// 運算式就逐一走訪。解不了的巨集（`matches!` 之類）略過。
    fn visit_macro(&mut self, m: &'ast syn::Macro) {
        if let Ok(args) = m.parse_body_with(Punctuated::<Expr, syn::Token![,]>::parse_terminated) {
            for a in &args {
                self.visit_expr(a);
            }
        }
    }
    fn visit_expr(&mut self, e: &'ast Expr) {
        match e {
            // 鏈的判定沒有副作用（不是鏈就回 false、什麼都不記），故可放在守衛裡
            Expr::MethodCall(m) if m.method == "var" && self.localized_chain(e) => return,
            Expr::Call(c) if is_localized_new(&c.func) && self.localized_chain(e) => return,
            Expr::MethodCall(m)
                if (m.method == "t" || m.method == "with_message") && m.args.len() == 2 =>
            {
                if let Some(key) = lit_str(&m.args[0]) {
                    let vars = var_array(&m.args[1]).map_or(Vars::Dynamic, Vars::Known);
                    let shape = if m.method == "t" { "t" } else { "with_message" };
                    self.site(shape, key, vars);
                }
            }
            Expr::Call(c) => {
                if let (Expr::Path(p), Some(key)) = (&*c.func, c.args.first().and_then(lit_str)) {
                    if p.path.segments.len() == 1 {
                        let f = p.path.segments[0].ident.to_string();
                        self.calls.push((self.file.clone(), f, key));
                    }
                }
            }
            _ => {}
        }
        visit::visit_expr(self, e);
    }
}

fn find(file: &str, src: &str) -> Finder {
    let ast = syn::parse_file(src).expect("解析 Rust 原始碼");
    let mut f = Finder {
        file: file.to_string(),
        ..Default::default()
    };
    f.visit_file(&ast);
    f
}

/// 把輔助函式的呼叫點轉成站點（只認 `helpers` 裡的函式）。
fn resolve_helpers(f: &mut Finder, helpers: &BTreeMap<String, BTreeSet<String>>) -> usize {
    let mut n = 0;
    for (file, func, key) in std::mem::take(&mut f.calls) {
        if let Some(vars) = helpers.get(&func) {
            n += 1;
            f.sites.push(Site {
                file,
                shape: "helper",
                key,
                vars: Vars::Known(vars.clone()),
            });
        }
    }
    n
}

#[test]
fn finder_sees_every_supported_shape() {
    let src = r#"
fn helper(key: &'static str, p: &str) -> Localized { Localized::new(key).var("path", p) }
fn a(cat: &Catalog, x: &str) {
    let _ = Localized::new("k.chain").var("a", x).var("b", x.len().to_string());
    let _ = cytrace_i18n::Localized::new("k.bare");
    eprintln!("{}", cat.t("k.macro", &[("m", x)]));
    let _ = api.with_message("k.msg", &[("v", x), ("w", "y")]);
    let _ = helper("k.helper", x);
    let vs = [("d", x)];
    let _ = cat.t("k.dynamic", &vs);
    let _ = Localized::new("k.nested").var("inner", cat.t("k.inner", &[]));
}
"#;
    let mut f = find("x.rs", src);
    let helpers = f.helpers.clone();
    assert_eq!(resolve_helpers(&mut f, &helpers), 1);
    let got: BTreeMap<String, Vars> = f
        .sites
        .iter()
        .map(|s| (s.key.clone(), s.vars.clone()))
        .collect();
    let k = |xs: &[&str]| Vars::Known(xs.iter().map(|s| s.to_string()).collect());
    let want: BTreeMap<String, Vars> = [
        ("k.chain", k(&["a", "b"])),
        ("k.bare", k(&[])),
        ("k.macro", k(&["m"])),
        ("k.msg", k(&["v", "w"])),
        ("k.helper", k(&["path"])),
        ("k.dynamic", Vars::Dynamic),
        ("k.nested", k(&["inner"])),
        ("k.inner", k(&[])),
    ]
    .into_iter()
    .map(|(a, b)| (a.to_string(), b))
    .collect();
    assert_eq!(got, want);
}

#[test]
fn code_vars_match_catalog_placeholders() {
    let sources = common::production_sources();
    common::assert_scope_not_vacuous(&sources, 30);
    let zh = catalog("zh-TW");
    let en = catalog("en-US");

    let mut all = Finder::default();
    for s in &sources.files {
        let f = find(&s.rel, &std::fs::read_to_string(&s.path).expect("讀原始碼"));
        all.sites.extend(f.sites);
        all.helpers.extend(f.helpers);
        all.calls.extend(f.calls);
        all.skipped_dynamic += f.skipped_dynamic;
    }
    let helpers = all.helpers.clone();
    let helper_sites = resolve_helpers(&mut all, &helpers);

    let mut checked = BTreeMap::<&str, usize>::new();
    let mut bad = Vec::new();
    let mut intentional_hit = BTreeSet::new();
    for s in &all.sites {
        let Vars::Known(vars) = &s.vars else { continue };
        let (Some(z), Some(e)) = (zh.get(&s.key), en.get(&s.key)) else {
            continue; // 鍵不存在由 i18n-check 把關
        };
        *checked.entry(s.shape).or_default() += 1;
        if let Some(i) = INTENTIONAL
            .iter()
            .position(|(f, k, _)| *f == s.file && *k == s.key && vars != z)
        {
            intentional_hit.insert(i);
            continue;
        }
        for (lang, want) in [("zh-TW", z), ("en-US", e)] {
            if vars != want {
                bad.push(format!(
                    "  {} {}「{}」：程式碼給 {:?}，{lang} 佔位符為 {:?}",
                    s.file, s.shape, s.key, vars, want
                ));
            }
        }
    }
    assert!(
        bad.is_empty(),
        "程式碼的插值變數與 catalog 佔位符不符（缺的會原樣印出 {{{{name}}}}，多的會被忽略）：\n{}",
        bad.join("\n")
    );

    let stale: Vec<_> = INTENTIONAL
        .iter()
        .enumerate()
        .filter(|(i, _)| !intentional_hit.contains(i))
        .map(|(_, (f, k, _))| format!("  {f}「{k}」"))
        .collect();
    assert!(
        stale.is_empty(),
        "INTENTIONAL 有項目沒命中（已修掉或改名——請從清單移除）：\n{}",
        stale.join("\n")
    );

    // 反空轉：三種形狀都要實際比到東西（數字是本檔撰寫時的實測下限，只該往上長）
    println!(
        "比對：{checked:?}，輔助函式呼叫 {helper_sites}，比不了而略過 {}",
        all.skipped_dynamic
    );
    let n = |k: &str| checked.get(k).copied().unwrap_or(0);
    assert!(
        n("Localized") >= 20 && n("t") >= 30 && n("with_message") >= 3 && helper_sites >= 3,
        "比對數量過少——解析可能已失效：{checked:?}，輔助函式呼叫 {helper_sites}，\
         比不了而略過 {} 處",
        all.skipped_dynamic
    );
}
