#[test]
fn cbom_keys_resolve() {
    let zh = cytrace_i18n::Catalog::load("zh-TW");
    let en = cytrace_i18n::Catalog::load("en-US");
    for k in [
        "cbom.err.empty_output",
        "cbom.err.timeout",
        "cbom.err.engine",
    ] {
        assert_ne!(zh.t(k, &[]), k, "zh 缺鍵 {k}");
        assert_ne!(en.t(k, &[]), k, "en 缺鍵 {k}");
    }
}
