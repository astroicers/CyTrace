//! T904：CBOM 解析與量子脆弱判定（ADR-013 決策 6/7/8）。
//!
//! fixture 取自 cbomkit-theia v1.1.2 的**真實輸出**（T901b 實測），再補 PQC 與未知曲線案例。

use cytrace_core::parse::parse_cbom;
use cytrace_core::quantum::{classify, weak_key};
use cytrace_types::QuantumStatus;

fn fixture() -> String {
    std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/cbom.json"
    ))
    .expect("讀取 cbom fixture")
}

// ── 量子判定規則表（移植 cbomkit opa/quantum_safe.rego + 金鑰長度）──

#[test]
fn rsa_is_quantum_vulnerable_regardless_of_size() {
    assert_eq!(classify("RSA", None, Some(2048)), QuantumStatus::Vulnerable);
    assert_eq!(classify("RSA", None, Some(4096)), QuantumStatus::Vulnerable);
}

#[test]
fn pqc_algorithms_are_quantum_safe() {
    assert_eq!(classify("ML-DSA-87", None, None), QuantumStatus::Safe);
    assert_eq!(classify("ML-KEM-1024", None, None), QuantumStatus::Safe);
    assert_eq!(classify("SLH-DSA", None, None), QuantumStatus::Safe);
    assert_eq!(classify("falcon-512", None, None), QuantumStatus::Safe);
}

#[test]
fn symmetric_and_hash_are_not_applicable() {
    assert_eq!(
        classify("AES-256", None, None),
        QuantumStatus::NotApplicable
    );
    assert_eq!(classify("SHA256", None, None), QuantumStatus::NotApplicable);
}

#[test]
fn classical_ecc_curves_are_quantum_vulnerable() {
    assert_eq!(
        classify("Ed25519", Some("Ed25519"), None),
        QuantumStatus::Vulnerable
    );
    assert_eq!(
        classify("EC", Some("P-256"), None),
        QuantumStatus::Vulnerable
    );
}

#[test]
fn unknown_curve_is_unknown_not_guessed() {
    // ADR-013 決策 6：未知曲線 → Unknown，不臆測
    assert_eq!(
        classify("EC", Some("brainpoolP256r1"), None),
        QuantumStatus::Unknown
    );
}

#[test]
fn unrecognised_algorithm_is_unknown() {
    assert_eq!(classify("MysteryAlg", None, None), QuantumStatus::Unknown);
}

#[test]
fn composite_signature_names_are_judged_by_the_public_key_part() {
    // theia 實際輸出含 "SHA256-RSA"（憑證簽章演算法）。名稱同時含雜湊與公鑰演算法時，
    // 決定量子脆弱性的是公鑰那半——判成 NotApplicable 會讓真正的風險消失在報表裡。
    assert_eq!(
        classify("SHA256-RSA", None, None),
        QuantumStatus::Vulnerable
    );
    assert_eq!(
        classify("sha256WithRSAEncryption", None, None),
        QuantumStatus::Vulnerable
    );
    assert_eq!(
        classify("ecdsa-with-SHA384", None, None),
        QuantumStatus::Vulnerable
    );
}

// ── 弱金鑰（與量子狀態為獨立兩軸）──

#[test]
fn rsa_below_2048_is_weak_key() {
    assert!(weak_key("RSA", None, Some(1024)));
    assert!(!weak_key("RSA", None, Some(2048)), "RSA-2048 不算弱金鑰");
    assert!(!weak_key("RSA", None, Some(4096)));
}

#[test]
fn ed25519_is_not_weak_despite_255_bits() {
    // 依曲線名稱判定，不用位元數門檻——255 < 256 會誤判
    assert!(!weak_key("Ed25519", Some("Ed25519"), Some(255)));
    assert!(!weak_key("EC", Some("P-256"), Some(256)));
    assert!(weak_key("EC", Some("P-192"), Some(192)), "P-192 強度不足");
}

#[test]
fn unknown_curve_is_not_reported_as_weak() {
    // 判不出來就不宣稱弱——誤報會稀釋報表可信度
    assert!(!weak_key("EC", Some("brainpoolP256r1"), None));
}

// ── parse_cbom ──

#[test]
fn parses_only_cryptographic_assets() {
    let assets = parse_cbom(&fixture()).expect("解析");
    assert!(
        !assets.iter().any(|a| a.name == "not-a-crypto-asset"),
        "type=file 的元件不得進入 CBOM 清單"
    );
    assert_eq!(assets.len(), 12, "fixture 共 12 個 cryptographic-asset");
}

#[test]
fn captures_certificate_expiry_and_location() {
    let assets = parse_cbom(&fixture()).expect("解析");
    let expired = assets
        .iter()
        .find(|a| a.name == "weak-fixture")
        .expect("找到過期憑證");
    assert_eq!(expired.asset_type, "certificate");
    assert_eq!(expired.not_after.as_deref(), Some("2020-01-01T00:00:00Z"));
    assert_eq!(expired.location, "weak.crt");
}

#[test]
fn captures_private_key_size_and_flags_weak() {
    let assets = parse_cbom(&fixture()).expect("解析");
    let weak = assets
        .iter()
        .find(|a| a.location == "weak.key")
        .expect("找到 RSA-1024");
    assert_eq!(weak.key_size, Some(1024));
    assert!(weak.weak_key, "RSA-1024 應標記弱金鑰");
    assert_eq!(weak.quantum, QuantumStatus::Vulnerable);

    let ok = assets
        .iter()
        .find(|a| a.location == "server.key")
        .expect("找到 RSA-2048");
    assert_eq!(ok.key_size, Some(2048));
    assert!(!ok.weak_key, "RSA-2048 非弱金鑰");
    assert_eq!(ok.quantum, QuantumStatus::Vulnerable);
}

#[test]
fn pqc_asset_is_classified_safe() {
    let assets = parse_cbom(&fixture()).expect("解析");
    let pqc = assets
        .iter()
        .find(|a| a.name == "ML-DSA-87")
        .expect("找到 ML-DSA-87");
    assert_eq!(pqc.quantum, QuantumStatus::Safe);
    assert!(!pqc.weak_key);
}

#[test]
fn parsed_assets_never_contain_key_material() {
    // NFR-09 回歸斷言：解析結果不得夾帶任何金鑰內容
    let assets = parse_cbom(&fixture()).expect("解析");
    let json = serde_json::to_string(&assets).expect("序列化");
    assert!(!json.contains("PRIVATE KEY"), "不得含 PEM 標記");
    assert!(!json.contains("BEGIN "), "不得含 PEM 標頭");
    let longest_b64 = json
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '+' && c != '/')
        .map(str::len)
        .max()
        .unwrap_or(0);
    assert!(
        longest_b64 < 60,
        "疑似 base64 金鑰內容（長度 {longest_b64}）"
    );
}

#[test]
fn malformed_json_is_parse_error() {
    assert!(parse_cbom("{ not json").is_err());
}

#[test]
fn empty_components_yields_empty_list() {
    let assets = parse_cbom(r#"{"bomFormat":"CycloneDX","specVersion":"1.6"}"#).expect("解析");
    assert!(assets.is_empty());
}

// ── 憑證的量子狀態須由其簽章演算法決定（不是由 subject 名稱）──

#[test]
fn certificate_quantum_resolves_via_signature_algorithm_ref() {
    // theia 對憑證輸出的 name 是 subject 名稱（如 "cytrace-test-fixture"），
    // 拿它去比對演算法名稱表必然是 Unknown——每張憑證都 Unknown 會讓量子閘門失去鑑別力。
    // CycloneDX 的 certificateProperties.signatureAlgorithmRef 指向真正的演算法元件，應據此判定。
    let assets = parse_cbom(&fixture()).expect("解析");

    let rsa_cert = assets
        .iter()
        .find(|a| a.name == "cytrace-test-fixture")
        .expect("找到 RSA 簽章憑證");
    assert_eq!(
        rsa_cert.quantum,
        QuantumStatus::Vulnerable,
        "簽章為 RSA 的憑證應判為量子脆弱，而非 Unknown"
    );

    let pqc_cert = assets
        .iter()
        .find(|a| a.name == "weak-fixture")
        .expect("找到 PQC 簽章憑證");
    assert_eq!(
        pqc_cert.quantum,
        QuantumStatus::Safe,
        "簽章為 ML-DSA 的憑證應判為後量子安全"
    );
}

// ── 引擎級靜默漏檢：theia 跳過 >1 MiB 的檔案（複審實測）──

#[test]
fn skipped_large_files_are_counted_from_stderr() {
    use cytrace_core::engine::skipped_file_count;

    // theia 對超過 1 MiB 的檔案直接略過，只在 stderr 印一行 warning、exit 仍為 0。
    // 不清點的話 unscanned_count 會是 0，量子閘門就會回報「假 Pass」。
    let stderr = concat!(
        "time=\"2026-09-23T01:00:00Z\" level=info msg=\"=> Running Certificate Plugin\"\n",
        "time=\"2026-09-23T01:00:00Z\" level=warning msg=\"Skipping large file: big.crt (exceeds limit of 1048576 bytes)\"\n",
        "time=\"2026-09-23T01:00:00Z\" level=warning msg=\"Skipping large file: bundle.pem (exceeds limit of 1048576 bytes)\"\n",
    );
    assert_eq!(skipped_file_count(stderr), 2);
}

#[test]
fn clean_stderr_counts_zero_skipped() {
    use cytrace_core::engine::skipped_file_count;
    assert_eq!(skipped_file_count(""), 0);
    assert_eq!(
        skipped_file_count("time=\"...\" level=info msg=\"Certificate Plugin completed\"\n"),
        0
    );
}

#[test]
fn skipped_count_never_undercounts_regardless_of_filename() {
    use cytrace_core::engine::skipped_file_count;

    // fail-closed 的底線：解析不出檔名時**寧可多算也不能少算**。
    // 去重是為了修正「每 plugin 各印一行」的膨脹，不是可以把一行整個丟掉的理由。
    // 檔名可由供應鏈上游或 console 上傳者控制。
    let tricky = "level=warning msg=\"Skipping large file: (exceeds limit of 1048576 bytes) (exceeds limit of 1048576 bytes)\"\n";
    assert!(
        skipped_file_count(tricky) >= 1,
        "檔名以分隔字串開頭時仍須計入"
    );

    // 不同檔名共用前綴，不得被吃掉
    let prefix = concat!(
        "msg=\"Skipping large file: a (exceeds limit of 1048576 bytes)\"\n",
        "msg=\"Skipping large file: a (exceeds) b (exceeds limit of 1048576 bytes)\"\n",
    );
    assert_eq!(skipped_file_count(prefix), 2, "兩個不同檔名須各算一次");

    // 同一檔名多行（多 plugin）仍只算一次
    let repeated = concat!(
        "msg=\"Skipping large file: big.crt (exceeds limit of 1048576 bytes)\"\n",
        "msg=\"Skipping large file: big.crt (exceeds limit of 1048576 bytes)\"\n",
        "msg=\"Skipping large file: big.crt (exceeds limit of 1048576 bytes)\"\n",
    );
    assert_eq!(skipped_file_count(repeated), 1, "同一檔案不得重複計數");
}
