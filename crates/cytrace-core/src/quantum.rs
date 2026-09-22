//! 量子脆弱判定（ADR-013 決策 6）。
//!
//! 規則移植自 cbomkit `opa/quantum_safe.rego`（Apache-2.0）：PQC 名稱白名單、
//! `nistQuantumSecurityLevel` 門檻、對稱演算法視為不適用；再補**金鑰長度**規則。
//!
//! **量子狀態與弱金鑰是兩條獨立的軸**：RSA-4096 量子脆弱但非弱金鑰；
//! P-192 非量子安全**且**強度不足。
//!
//! 判不出來一律 [`QuantumStatus::Unknown`]／非弱金鑰——**不臆測**（軍規場域寧可標示未知，
//! 也不可給出無根據的安全宣稱）。

use cytrace_types::QuantumStatus;

/// 後量子演算法名稱片段（小寫比對）。取自 `quantum_safe.rego` 的白名單。
const PQC_NAMES: &[&str] = &[
    "ml-kem",
    "ml-dsa",
    "slh-dsa",
    "kyber",
    "dilithium",
    "falcon",
    "sphincs",
    "xmss",
    "lms",
    "frodokem",
    "hqc",
    "mceliece",
    "bike",
    "ntru",
];

/// 古典（量子脆弱）公鑰演算法名稱片段。
const CLASSICAL_PK_NAMES: &[&str] = &[
    "rsa", "dsa", "ecdsa", "ecdh", "dh", "elgamal", "ed25519", "ed448", "x25519", "x448",
];

/// 對稱 / 雜湊 / MAC 等非公鑰演算法名稱片段 → 量子判定不適用。
const SYMMETRIC_NAMES: &[&str] = &[
    "aes", "sha", "sha1", "sha2", "sha3", "hmac", "chacha", "poly1305", "blake", "md5", "3des",
    "des", "camellia", "shake",
];

/// 已知古典橢圓曲線 → (曲線名, 古典安全強度 bits)。
///
/// **依曲線名稱判定，不用位元數門檻**：Ed25519 常回報 255 bit，位元數門檻會誤判為弱金鑰。
const KNOWN_CURVES: &[(&str, u32)] = &[
    ("ed25519", 128),
    ("x25519", 128),
    ("ed448", 224),
    ("x448", 224),
    ("p-256", 128),
    ("secp256r1", 128),
    ("prime256v1", 128),
    ("p-384", 192),
    ("secp384r1", 192),
    ("p-521", 256),
    ("secp521r1", 256),
    ("secp256k1", 128),
    ("p-224", 112),
    ("secp224r1", 112),
    ("p-192", 96),
    ("secp192r1", 96),
];

/// NIST 量子安全等級達此值以上即視為後量子安全（`quantum_safe.rego` 門檻）。
const MIN_NIST_LEVEL: u8 = 1;

/// 古典安全強度低於此值視為弱金鑰（NIST SP 800-57 最低可接受強度）。
const MIN_CLASSICAL_STRENGTH_BITS: u32 = 112;

/// RSA 最小可接受模數長度。
const MIN_RSA_BITS: u32 = 2048;

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|n| haystack.contains(n))
}

fn curve_strength(curve: &str) -> Option<u32> {
    let c = curve.trim().to_ascii_lowercase();
    KNOWN_CURVES
        .iter()
        .find(|(name, _)| c == *name)
        .map(|(_, bits)| *bits)
}

/// 依演算法名稱、曲線與金鑰長度判定量子脆弱性。
///
/// 判定順序：NIST 等級 → PQC 名稱 → 對稱/雜湊 → 已知曲線 → 古典公鑰名稱 → 未知。
pub fn classify(name: &str, curve: Option<&str>, _key_size: Option<u32>) -> QuantumStatus {
    classify_with_level(name, curve, None)
}

/// 同 [`classify`]，但可帶入 CycloneDX 的 `nistQuantumSecurityLevel`。
pub fn classify_with_level(
    name: &str,
    curve: Option<&str>,
    nist_level: Option<u8>,
) -> QuantumStatus {
    let n = name.trim().to_ascii_lowercase();

    if let Some(level) = nist_level {
        if level >= MIN_NIST_LEVEL {
            return QuantumStatus::Safe;
        }
    }
    if contains_any(&n, PQC_NAMES) {
        return QuantumStatus::Safe;
    }
    // 公鑰演算法優先於對稱／雜湊：theia 會輸出 `SHA256-RSA`、`sha256WithRSAEncryption`
    // 這類複合簽章名稱，決定量子脆弱性的是公鑰那一半。先比對雜湊會讓真實風險消失。
    if contains_any(&n, CLASSICAL_PK_NAMES) {
        return QuantumStatus::Vulnerable;
    }
    if contains_any(&n, SYMMETRIC_NAMES) {
        return QuantumStatus::NotApplicable;
    }
    if let Some(c) = curve {
        return match curve_strength(c) {
            // 已知古典曲線 → 可被 Shor 破解
            Some(_) => QuantumStatus::Vulnerable,
            // 未知曲線 → 不臆測
            None => QuantumStatus::Unknown,
        };
    }
    QuantumStatus::Unknown
}

/// 弱金鑰判定（與量子狀態獨立）。
///
/// - RSA：模數 < 2048 bit
/// - ECC：**依曲線名稱**查古典安全強度，< 112 bit 視為弱
/// - 未知曲線或缺長度資訊 → 不宣稱為弱
pub fn weak_key(name: &str, curve: Option<&str>, key_size: Option<u32>) -> bool {
    let n = name.trim().to_ascii_lowercase();

    if let Some(c) = curve {
        return match curve_strength(c) {
            Some(bits) => bits < MIN_CLASSICAL_STRENGTH_BITS,
            None => false,
        };
    }
    if n.contains("rsa") {
        return key_size.is_some_and(|bits| bits < MIN_RSA_BITS);
    }
    false
}
