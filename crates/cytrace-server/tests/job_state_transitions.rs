//! #43：job 轉成 running 只能經 `JobRegistry::start_if_queued`。
//!
//! 它與 `cancel_if_queued` 在同一把寫鎖內檢查並轉移，兩者互斥；若改回「先 get 檢查 queued、
//! 再 update 轉 running」，取消可能落在兩步之間：input/ 已被刪，runner 卻照樣掃描（#39 複審）。
//! 這個競態在整合層無法穩定重現，故以原始碼結構把關。
//!
//! **規則**：生產碼裡，凡是在「值的位置」出現名稱為 `Running` 的路徑，都必須位於
//! `start_if_queued` 之內。不論前綴（`JobStatus::Running`、`super::JobStatus::Running`、
//! 別名 `S::Running`、glob 匯入後的裸名 `Running`），也不論用途（賦值、結構字面值、函式參數、
//! `if` 的分支值、`mem::replace`、先存進變數再用）。這樣通用 setter（`set_status(id, Running)`）
//! 這類間接寫法也會被抓到。
//!
//! **不算**：`==`／`!=` 比較的運算元、pattern（`match` 分支、`if let`）、`#[cfg(test)]` 的模組與函式。
//!
//! **已知盲點**（不會被這支檢查發現，須另行審查）：
//! - 巨集的內容不展開（如 `macro_rules!` 本體、`matches!` 的引數）。
//! - 不經名稱建構出 running 的寫法，例如從字串反序列化（`"running"`）或 `transmute`。
//!
//! 誤報（例如另一個型別也有名為 `Running` 的變體）會讓檢查轉紅，屬 fail-closed；屆時在此顯式豁免。

mod common;

use syn::visit::{self, Visit};
use syn::{BinOp, Expr};

/// 唯一允許出現 running 值的函式。
const ALLOWED_FN: &str = "start_if_queued";

/// 一處「值的位置出現 Running」：（檔案，所在函式）。
type Hit = (String, String);

#[derive(Default)]
struct Finder {
    file: String,
    fn_stack: Vec<String>,
    test_depth: usize,
    pat_depth: usize,
    hits: Vec<Hit>,
}

/// 路徑的最後一段是否為 `Running`（不論前綴）。
fn ends_with_running(p: &syn::ExprPath) -> bool {
    p.path.segments.last().is_some_and(|s| s.ident == "Running")
}

fn is_running_path(e: &Expr) -> bool {
    matches!(e, Expr::Path(p) if ends_with_running(p))
}

impl<'ast> Visit<'ast> for Finder {
    fn visit_item_mod(&mut self, m: &'ast syn::ItemMod) {
        let test = common::is_cfg_test(&m.attrs);
        self.test_depth += usize::from(test);
        visit::visit_item_mod(self, m);
        self.test_depth -= usize::from(test);
    }
    fn visit_item_fn(&mut self, f: &'ast syn::ItemFn) {
        let test = common::is_cfg_test(&f.attrs);
        self.test_depth += usize::from(test);
        self.fn_stack.push(f.sig.ident.to_string());
        visit::visit_item_fn(self, f);
        self.fn_stack.pop();
        self.test_depth -= usize::from(test);
    }
    fn visit_impl_item_fn(&mut self, f: &'ast syn::ImplItemFn) {
        let test = common::is_cfg_test(&f.attrs);
        self.test_depth += usize::from(test);
        self.fn_stack.push(f.sig.ident.to_string());
        visit::visit_impl_item_fn(self, f);
        self.fn_stack.pop();
        self.test_depth -= usize::from(test);
    }
    /// pattern 裡的 `JobStatus::Running`（`match` 分支、`if let`）是比對，不是設值。
    fn visit_pat(&mut self, p: &'ast syn::Pat) {
        self.pat_depth += 1;
        visit::visit_pat(self, p);
        self.pat_depth -= 1;
    }
    /// `==`／`!=` 的運算元是比對，不是設值；其餘照常走訪。
    fn visit_expr_binary(&mut self, b: &'ast syn::ExprBinary) {
        if matches!(b.op, BinOp::Eq(_) | BinOp::Ne(_)) {
            for side in [&*b.left, &*b.right] {
                if !is_running_path(side) {
                    self.visit_expr(side);
                }
            }
            return;
        }
        visit::visit_expr_binary(self, b);
    }
    fn visit_expr_path(&mut self, p: &'ast syn::ExprPath) {
        if self.pat_depth == 0 && self.test_depth == 0 && ends_with_running(p) {
            let f = self.fn_stack.last().cloned().unwrap_or_default();
            self.hits.push((self.file.clone(), f));
        }
        visit::visit_expr_path(self, p);
    }
}

fn scan(file: &str, src: &str) -> Vec<Hit> {
    let ast = syn::parse_file(src).unwrap_or_else(|e| panic!("{file} 解析失敗：{e}"));
    let mut f = Finder {
        file: file.to_string(),
        ..Default::default()
    };
    f.visit_file(&ast);
    f.hits
}

#[test]
fn only_start_if_queued_produces_running() {
    let sources = common::production_sources();
    common::assert_scope_not_vacuous(&sources, 20);

    let mut hits = Vec::new();
    for s in &sources.files {
        let src = std::fs::read_to_string(&s.path).expect("讀生產碼");
        hits.extend(scan(&s.rel, &src));
    }

    let (allowed, offending): (Vec<_>, Vec<_>) = hits.into_iter().partition(|(file, f)| {
        file == "crates/cytrace-server/src/jobs/registry.rs" && f == ALLOWED_FN
    });
    assert!(
        offending.is_empty(),
        "以下位置在 `JobRegistry::start_if_queued` 之外產生 running 值——可能繞過與取消互斥的\
         單一入口，讓取消落在檢查與轉移之間、刪掉正被掃描的 input/（#43）：{offending:?}"
    );
    // 反空轉：唯一的合法入口必須被偵測到，否則偵測器或掃描範圍已失效
    assert_eq!(
        allowed.len(),
        1,
        "預期在 registry.rs 的 {ALLOWED_FN} 內偵測到恰好一處 running 值"
    );
}

/// 必紅哨兵：#39 修正前 runner 的兩步寫法，以及其他會繞過單一入口的寫法，都必須被抓到。
#[test]
fn detector_flags_indirect_ways_to_produce_running() {
    let must_flag = [
        // #39 修正前的 runner：先 get 檢查、再 update 轉 running
        r#"fn spawn() { app.jobs.update(&id, |r| { r.status = JobStatus::Running; }); }"#,
        // closure 單行形、完整路徑
        r#"fn spawn() { app.jobs.update(&id, |r| r.status = super::JobStatus::Running); }"#,
        // 結構字面值
        r#"fn mk() -> JobRecord { JobRecord { status: JobStatus::Running, ..base } }"#,
        // registry 的其他方法
        r#"impl JobRegistry { fn resume(&self) { record.status = JobStatus::Running; } }"#,
        // 通用 setter：呼叫端以參數傳入（第三輪複審指出的退化路徑）
        r#"fn spawn() { app.jobs.set_status(&id, JobStatus::Running); }"#,
        // 別名
        r#"use JobStatus as S; fn spawn() { r.status = S::Running; }"#,
        // glob 匯入後的裸名
        r#"use JobStatus::*; fn spawn() { r.status = Running; }"#,
        // if 的分支值
        r#"fn spawn() { r.status = if go { JobStatus::Running } else { JobStatus::Queued }; }"#,
        // mem::replace
        r#"fn spawn() { std::mem::replace(&mut r.status, JobStatus::Running); }"#,
        // 先存進變數，再以結構簡寫帶入
        r#"fn mk() -> JobRecord { let status = JobStatus::Running; JobRecord { status, ..base } }"#,
    ];
    for (i, src) in must_flag.iter().enumerate() {
        assert_eq!(scan("sample.rs", src).len(), 1, "樣本 {i} 未被偵測：{src}");
    }

    // 必綠：比較、pattern、cfg(test)（模組與函式）、其他狀態，都不算
    let must_pass = [
        r#"fn f() { if r.status == JobStatus::Running {} }"#,
        r#"fn f() { if JobStatus::Running != r.status {} }"#,
        r#"fn f() { match s { JobStatus::Running => {}, _ => {} } }"#,
        r#"fn f() { if let JobStatus::Running = s {} }"#,
        r#"fn f() { r.status = JobStatus::Canceled; }"#,
        r#"#[cfg(test)] mod tests { fn t() { r.status = JobStatus::Running; } }"#,
        r#"#[cfg(test)] fn t() { r.status = JobStatus::Running; }"#,
    ];
    for (i, src) in must_pass.iter().enumerate() {
        assert!(
            scan("sample.rs", src).is_empty(),
            "樣本 {i} 不應被偵測：{src}"
        );
    }
}
