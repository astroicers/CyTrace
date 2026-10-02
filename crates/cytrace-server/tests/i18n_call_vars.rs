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
//! 比不了的兩種，都不准悄悄略過（T912 複審 newgates#3／#4、claims#12）：
//! - 鍵是字面值、變數清單不是字面值陣列（`&vars`）——**必須為 0**；
//! - 鍵不是字面值（`t(risk.i18n_key(), &[])`）——逐筆列在 [`NONLITERAL`]，次數必須完全相符，
//!   每筆寫明由哪支測試涵蓋。新增這種呼叫就會轉紅，逼人補上涵蓋。
//!   含 UFCS（`Catalog::t(cat, k, …)`）、鍵不是外層參數的 `Localized::new(x.i18n_key())`、
//!   以非字面值鍵呼叫輔助函式；
//! - 解析不了、又含 i18n 呼叫的巨集（`macro_rules!` 本體）——**必須為空**。
//!
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

/// 鍵不是字面值的 `.t`／`.with_message` 呼叫：（檔案, 鍵運算式, 出現次數, 由誰涵蓋）。
const NONLITERAL: &[(&str, &str, usize, &str)] = &[
    (
        "crates/cytrace-cli/src/main.rs",
        "other.i18n_key()",
        1,
        "CytraceError 的分類鍵、空變數：main.rs core_errors_render_in_the_operator_language 逐變體驗無 {{",
    ),
    (
        "crates/cytrace-cli/src/main.rs",
        "key",
        1,
        "schema_warning 回傳的 cli.schema_ahead：operator_lang.rs report_on_a_newer_schema_names_both_versions",
    ),
    (
        "crates/cytrace-cli/src/main.rs",
        "risk.i18n_key()",
        1,
        "Severity 鍵、空變數：main.rs every_severity_label_renders_without_variables",
    ),
    (
        "crates/cytrace-i18n/src/lib.rs",
        "self.key",
        1,
        "Localized::render 的管線；各 Localized 建構點由本檔比對",
    ),
    (
        "crates/cytrace-server/src/api/jobs.rs",
        "ae.i18n_key()",
        1,
        "ArchiveError 鍵、空變數：archive.rs every_archive_error_message_renders_without_variables",
    ),
    (
        "crates/cytrace-server/src/api/jobs.rs",
        "k",
        1,
        "job 錯誤的退回鏈（server.err.{kind}／server.job.*）：tests/jobs.rs 的 message 斷言無 {{",
    ),
    (
        "crates/cytrace-server/src/error.rs",
        "k",
        1,
        "with_message 存下的鍵與變數的管線；各 with_message 呼叫點由本檔比對",
    ),
    (
        "crates/cytrace-server/src/error.rs",
        "&k",
        1,
        "ErrorKind 鍵、空變數：error.rs every_kind_message_renders_without_variables",
    ),
];

fn placeholders(s: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut rest = s;
    while let Some(i) = rest.find("{{") {
        let after = &rest[i + 2..];
        let Some(j) = after.find("}}") else { break };
        // 不 trim：與執行期的 `interpolate` 同一規則（名稱全文比對）。trim 的話，
        // locale 寫成 `{{ addr }}` 會在這裡比對成功、執行時卻原樣印出（複審 newgates#2）
        out.insert(after[..j].to_string());
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
    /// 外層函式：（名稱, 參數名）。參數名用來判定 `Localized::new(key)` 的 key 是不是參數。
    fn_stack: Vec<(String, Vec<String>)>,
    /// 解析不了、又含 i18n 呼叫的巨集：（檔案, 巨集名）。比不到就等於沒驗，必須為空。
    unparsed: Vec<(String, String)>,
    sites: Vec<Site>,
    /// 以參數當鍵建 `Localized` 的函式 → 它補上的變數。
    helpers: BTreeMap<String, BTreeSet<String>>,
    /// 單一識別字函式、第一個引數是字串字面值的呼叫：（檔案, 函式名, 鍵）。
    calls: Vec<(String, String, String)>,
    /// 鍵是字面值、但變數清單比不了的呼叫數。
    skipped_dynamic: usize,
    /// 鍵不是字面值的 `.t`／`.with_message` 呼叫：（檔案, 鍵運算式）。只記生產碼——
    /// 測試碼以非字面值鍵呼叫，本身就是在驗那些鍵。
    nonliteral: Vec<(String, String)>,
    /// 單一識別字函式、第一個引數不是字面值的呼叫：（檔案, 函式名, 鍵運算式）。
    helper_nonliteral: Vec<(String, String, String)>,
    /// 目前在幾層 `#[cfg(test)]` 模組裡。
    test_depth: usize,
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
                // 鍵是**外層函式的參數**：記為輔助函式，呼叫點另行比對。
                // 其他非字面值鍵（`Localized::new(x.i18n_key())`）計入 NONLITERAL——前版一律
                // 當輔助函式，於是這種形狀既不比對、也不計數（第三輪複審）
                let param = match &c.args[0] {
                    Expr::Path(p) if p.path.segments.len() == 1 => {
                        let id = p.path.segments[0].ident.to_string();
                        self.fn_stack
                            .last()
                            .filter(|(_, params)| params.contains(&id))
                            .map(|(f, _)| f.clone())
                    }
                    _ => None,
                };
                match (param, dynamic) {
                    (Some(f), false) => {
                        self.helpers.insert(f, names);
                    }
                    _ => self.nonliteral_site("Localized::new", &c.args[0]),
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

impl Finder {
    fn nonliteral_site(&mut self, shape: &str, key: &Expr) {
        if self.test_depth == 0 {
            use quote::ToTokens;
            let k = key.to_token_stream().to_string().replace(' ', "");
            let k = if shape == "Localized::new" {
                format!("Localized::new({k})")
            } else {
                k
            };
            self.nonliteral.push((self.file.clone(), k));
        }
    }

    /// `.t(k, vars)`／`.with_message(k, vars)`，或 UFCS 的 `Catalog::t(cat, k, vars)`。
    fn keyed_call(&mut self, method: &str, key: &Expr, vars: &Expr) {
        match lit_str(key) {
            Some(k) => {
                let v = var_array(vars).map_or(Vars::Dynamic, Vars::Known);
                let shape = if method == "t" { "t" } else { "with_message" };
                self.site(shape, k, v);
            }
            None => self.nonliteral_site(method, key),
        }
    }
}

fn params_of(sig: &syn::Signature) -> Vec<String> {
    sig.inputs
        .iter()
        .filter_map(|a| match a {
            syn::FnArg::Typed(t) => match &*t.pat {
                syn::Pat::Ident(i) => Some(i.ident.to_string()),
                _ => None,
            },
            syn::FnArg::Receiver(_) => None,
        })
        .collect()
}

/// token 裡是否有 i18n 呼叫的跡象：`Localized`、`with_message`、或 `.t(`。
fn mentions_i18n(ts: proc_macro2::TokenStream) -> bool {
    use proc_macro2::TokenTree as T;
    let toks: Vec<T> = ts.into_iter().collect();
    toks.iter().enumerate().any(|(i, t)| match t {
        T::Ident(id) => {
            id == "Localized"
                || id == "with_message"
                || (id == "t"
                    && matches!(i.checked_sub(1).and_then(|j| toks.get(j)), Some(T::Punct(p)) if p.as_char() == '.')
                    && matches!(toks.get(i + 1), Some(T::Group(g)) if g.delimiter() == proc_macro2::Delimiter::Parenthesis))
        }
        T::Group(g) => mentions_i18n(g.stream()),
        _ => false,
    })
}

impl<'ast> Visit<'ast> for Finder {
    fn visit_item_mod(&mut self, m: &'ast syn::ItemMod) {
        let test = common::is_cfg_test(&m.attrs);
        self.test_depth += usize::from(test);
        visit::visit_item_mod(self, m);
        self.test_depth -= usize::from(test);
    }
    fn visit_item_fn(&mut self, f: &'ast syn::ItemFn) {
        self.fn_stack
            .push((f.sig.ident.to_string(), params_of(&f.sig)));
        visit::visit_item_fn(self, f);
        self.fn_stack.pop();
    }
    fn visit_impl_item_fn(&mut self, f: &'ast syn::ImplItemFn) {
        self.fn_stack
            .push((f.sig.ident.to_string(), params_of(&f.sig)));
        visit::visit_impl_item_fn(self, f);
        self.fn_stack.pop();
    }
    /// 格式巨集（`eprintln!("{}", cat.t(…))`）的參數 syn 不會自動解析；能解成逗號分隔的
    /// 運算式就逐一走訪。解不了的巨集（`matches!`、`macro_rules!` 本體）若含 i18n 呼叫，
    /// 記入 `unparsed`——前版直接略過，`macro_rules!` 本體裡配錯變數完全看不到（第三輪複審）。
    fn visit_macro(&mut self, m: &'ast syn::Macro) {
        match m.parse_body_with(Punctuated::<Expr, syn::Token![,]>::parse_terminated) {
            Ok(args) => {
                for a in &args {
                    self.visit_expr(a);
                }
            }
            Err(_) if self.test_depth == 0 && mentions_i18n(m.tokens.clone()) => {
                use quote::ToTokens;
                let name = m.path.to_token_stream().to_string().replace(' ', "");
                self.unparsed.push((self.file.clone(), name));
            }
            Err(_) => {}
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
                let method = m.method.to_string();
                self.keyed_call(&method, &m.args[0], &m.args[1]);
            }
            // UFCS：`Catalog::t(cat, k, vars)`
            Expr::Call(c)
                if c.args.len() == 3
                    && matches!(&*c.func, Expr::Path(p) if p.path.segments.len() >= 2
                        && p.path.segments.last().is_some_and(|s| s.ident == "t" || s.ident == "with_message")) =>
            {
                let Expr::Path(p) = &*c.func else {
                    unreachable!()
                };
                let method = p.path.segments.last().unwrap().ident.to_string();
                self.keyed_call(&method, &c.args[1], &c.args[2]);
            }
            Expr::Call(c) => {
                if let (Expr::Path(p), Some(first)) = (&*c.func, c.args.first()) {
                    if p.path.segments.len() == 1 {
                        let f = p.path.segments[0].ident.to_string();
                        match lit_str(first) {
                            Some(key) => self.calls.push((self.file.clone(), f, key)),
                            // 輔助函式以非字面值鍵呼叫：等知道哪些是輔助函式後再計入 NONLITERAL
                            None if self.test_depth == 0 => {
                                use quote::ToTokens;
                                let k = first.to_token_stream().to_string().replace(' ', "");
                                self.helper_nonliteral.push((self.file.clone(), f, k));
                            }
                            None => {}
                        }
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
    for (file, func, k) in std::mem::take(&mut f.helper_nonliteral) {
        if helpers.contains_key(&func) {
            f.nonliteral.push((file, format!("{func}({k})")));
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
    let _ = cat.t(risk.i18n_key(), &[]);
    let _ = Localized::new(x.i18n_key()).var("v", x);
    let _ = Catalog::t(cat, "k.ufcs", &[("u", x)]);
    let _ = helper(other.key(), x);
}
macro_rules! m { ($c:expr) => { $c.t("k.inmacro", &[("w", "x")]) }; }
#[cfg(test)]
mod tests {
    fn t(cat: &Catalog, k: &str) { let _ = cat.t(k, &[]); }
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
        ("k.ufcs", k(&["u"])),
    ]
    .into_iter()
    .map(|(a, b)| (a.to_string(), b))
    .collect();
    assert_eq!(got, want);
    // 鍵非字面值：生產碼記下（含非參數鍵的 Localized::new、輔助函式的非字面值呼叫），
    // cfg(test) 模組內不記
    let nl: Vec<&str> = f.nonliteral.iter().map(|(_, k)| k.as_str()).collect();
    assert_eq!(
        nl,
        [
            "risk.i18n_key()",
            "Localized::new(x.i18n_key())",
            "helper(other.key())"
        ]
    );
    // 解析不了的巨集本體裡有 i18n 呼叫：記下
    assert_eq!(
        f.unparsed,
        vec![("x.rs".to_string(), "macro_rules".to_string())]
    );
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
        all.nonliteral.extend(f.nonliteral);
        all.helper_nonliteral.extend(f.helper_nonliteral);
        all.unparsed.extend(f.unparsed);
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

    assert_eq!(
        all.skipped_dynamic, 0,
        "有鍵是字面值、但變數清單不是字面值陣列的呼叫（如 `let v = [..]; t(\"k\", &v)`）——\
         比不了就等於沒驗；請改寫成 `t(\"k\", &[(\"a\", …)])`"
    );

    assert!(
        all.unparsed.is_empty(),
        "有解析不了、又含 i18n 呼叫的巨集（比不到就等於沒驗；請把呼叫移出巨集本體）：{:?}",
        all.unparsed
    );

    // 鍵不是字面值的呼叫：與 NONLITERAL 逐筆、逐次數相符
    let mut drift = Vec::new();
    let mut counted = BTreeMap::<(&str, &str), usize>::new();
    for (f, k) in &all.nonliteral {
        *counted.entry((f.as_str(), k.as_str())).or_default() += 1;
    }
    for ((f, k), n) in &counted {
        let want = NONLITERAL
            .iter()
            .find(|(nf, nk, _, _)| nf == f && nk == k)
            .map_or(0, |e| e.2);
        if *n != want {
            drift.push(format!("  {f}「{k}」：實際 {n} 處，清單記 {want} 處"));
        }
    }
    for (nf, nk, want, _) in NONLITERAL {
        if !counted.contains_key(&(*nf, *nk)) {
            drift.push(format!(
                "  {nf}「{nk}」：實際 0 處，清單記 {want} 處（已移除——請更新清單）"
            ));
        }
    }
    assert!(
        drift.is_empty(),
        "鍵不是字面值的呼叫與 NONLITERAL 不符（新增的請寫明由哪支測試驗它不殘留 {{{{…}}}}）：\n{}",
        drift.join("\n")
    );

    // 反空轉：三種形狀都要實際比到東西（數字是本檔撰寫時的實測下限，只該往上長）
    println!(
        "比對：{checked:?}，輔助函式呼叫 {helper_sites}，變數比不了 {}，鍵非字面值 {}",
        all.skipped_dynamic,
        all.nonliteral.len()
    );
    let n = |k: &str| checked.get(k).copied().unwrap_or(0);
    assert!(
        n("Localized") >= 20 && n("t") >= 30 && n("with_message") >= 3 && helper_sites >= 3,
        "比對數量過少——解析可能已失效：{checked:?}，輔助函式呼叫 {helper_sites}"
    );
}
