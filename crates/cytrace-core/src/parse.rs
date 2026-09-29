//! 解析 Grype JSON 與 CycloneDX SBOM → 統一型別（FR-003 / SDS §4）。
//!
//! 只擷取需要的欄位，其餘以 `#[serde(default)]` 容忍，避免上游 schema 微調即失敗。

use crate::error::{CytraceError, Result};
use crate::quantum;
use cytrace_types::{Component, CryptoAsset, Severity, Vulnerability};
use serde::Deserialize;

// ─── Grype JSON（子集）─────────────────────────────────────────────
#[derive(Deserialize)]
struct GrypeDoc {
    #[serde(default)]
    matches: Vec<GrypeMatch>,
}

#[derive(Deserialize)]
struct GrypeMatch {
    vulnerability: GrypeVuln,
    artifact: GrypeArtifact,
}

#[derive(Deserialize)]
struct GrypeVuln {
    id: String,
    #[serde(default)]
    severity: String,
    #[serde(default, rename = "dataSource")]
    data_source: String,
    #[serde(default)]
    fix: Option<GrypeFix>,
    #[serde(default)]
    cvss: Vec<GrypeCvss>,
}

#[derive(Deserialize)]
struct GrypeFix {
    #[serde(default)]
    versions: Vec<String>,
}

#[derive(Deserialize)]
struct GrypeCvss {
    #[serde(default)]
    metrics: GrypeCvssMetrics,
}

#[derive(Deserialize, Default)]
struct GrypeCvssMetrics {
    #[serde(default, rename = "baseScore")]
    base_score: Option<f64>,
}

#[derive(Deserialize)]
struct GrypeArtifact {
    #[serde(default)]
    name: String,
}

/// 解析 Grype JSON 輸出為弱點清單。
pub fn parse_grype(json: &str) -> Result<Vec<Vulnerability>> {
    let doc: GrypeDoc =
        serde_json::from_str(json).map_err(|e| CytraceError::Parse(format!("grype: {e}")))?;
    Ok(doc
        .matches
        .into_iter()
        .map(|m| Vulnerability {
            id: m.vulnerability.id,
            severity: Severity::from_grype_str(&m.vulnerability.severity),
            cvss: m
                .vulnerability
                .cvss
                .into_iter()
                .find_map(|c| c.metrics.base_score),
            component: m.artifact.name,
            fixed_version: m
                .vulnerability
                .fix
                .and_then(|f| f.versions.into_iter().next()),
            source: m.vulnerability.data_source,
        })
        .collect())
}

// ─── CycloneDX（子集）──────────────────────────────────────────────
#[derive(Deserialize)]
struct CycloneDoc {
    #[serde(default)]
    components: Vec<CycloneComponent>,
}

#[derive(Deserialize)]
struct CycloneComponent {
    #[serde(default)]
    name: String,
    #[serde(default)]
    version: String,
    #[serde(default, rename = "type")]
    kind: String,
    #[serde(default)]
    licenses: Vec<CycloneLicenseEntry>,
}

#[derive(Deserialize)]
struct CycloneLicenseEntry {
    #[serde(default)]
    license: Option<CycloneLicense>,
    #[serde(default)]
    expression: Option<String>,
}

#[derive(Deserialize)]
struct CycloneLicense {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    name: Option<String>,
}

/// 解析 CycloneDX SBOM 為元件清單（→ 軟體產品文件表）。
pub fn parse_cyclonedx(json: &str) -> Result<Vec<Component>> {
    let doc: CycloneDoc =
        serde_json::from_str(json).map_err(|e| CytraceError::Parse(format!("cyclonedx: {e}")))?;
    Ok(doc
        .components
        .into_iter()
        .map(|c| {
            let licenses = c
                .licenses
                .into_iter()
                .filter_map(|e| {
                    e.expression
                        .or_else(|| e.license.and_then(|l| l.id.or(l.name)))
                })
                .collect();
            Component {
                name: c.name,
                version: c.version,
                kind: c.kind,
                licenses,
            }
        })
        .collect())
}

// ─── CBOM（CycloneDX cryptographic-asset 子集；ADR-013 決策 7）────────
//
// 只取判定與報表需要的欄位——**絕不**取金鑰內容（NFR-09）。
// 容忍 1.6 / 1.7：兩版的 cryptoProperties 形狀在本子集內相同。

#[derive(Deserialize)]
struct CbomDoc {
    /// theia 對**零資產目標**輸出的是 `"components": null`（非缺鍵、非空陣列），
    /// 故必須容忍 null——否則最常見的輸入（乾淨來源樹）會被判成解析失敗，
    /// 交件報表上寫「盤點失敗」，`--fail-on-quantum-vulnerable` 也恆 exit 1。
    #[serde(default)]
    components: Option<Vec<CbomComponent>>,
}

#[derive(Deserialize, Clone)]
struct CbomComponent {
    #[serde(default, rename = "bom-ref")]
    bom_ref: Option<String>,
    #[serde(default)]
    name: String,
    #[serde(default, rename = "type")]
    kind: String,
    #[serde(default, rename = "cryptoProperties")]
    crypto_properties: Option<CryptoProps>,
    #[serde(default)]
    evidence: Option<CbomEvidence>,
}

#[derive(Deserialize, Clone)]
struct CbomEvidence {
    #[serde(default)]
    occurrences: Vec<CbomOccurrence>,
}

#[derive(Deserialize, Clone)]
struct CbomOccurrence {
    #[serde(default)]
    location: String,
}

#[derive(Deserialize, Clone)]
struct CryptoProps {
    #[serde(default, rename = "assetType")]
    asset_type: String,
    #[serde(default, rename = "algorithmProperties")]
    algorithm: Option<AlgorithmProps>,
    #[serde(default, rename = "certificateProperties")]
    certificate: Option<CertificateProps>,
    #[serde(default, rename = "relatedCryptoMaterialProperties")]
    material: Option<MaterialProps>,
}

#[derive(Deserialize, Clone)]
struct AlgorithmProps {
    #[serde(default)]
    primitive: Option<String>,
    #[serde(default)]
    curve: Option<String>,
    #[serde(default, rename = "nistQuantumSecurityLevel")]
    nist_level: Option<u8>,
}

#[derive(Deserialize, Clone)]
struct CertificateProps {
    #[serde(default, rename = "notValidAfter")]
    not_valid_after: Option<String>,
    /// 指向簽章演算法元件的 bom-ref（CycloneDX）。
    #[serde(default, rename = "signatureAlgorithmRef")]
    signature_algorithm_ref: Option<String>,
    /// 指向公鑰材料元件的 bom-ref。
    #[serde(default, rename = "subjectPublicKeyRef")]
    subject_public_key_ref: Option<String>,
}

#[derive(Deserialize, Clone)]
struct MaterialProps {
    #[serde(default, rename = "type")]
    kind: Option<String>,
    #[serde(default)]
    size: Option<u32>,
}

/// 解析 theia 產出的 CBOM，取出密碼學資產並完成量子／弱金鑰判定。
///
/// 只保留 `type == "cryptographic-asset"` 的元件；其餘（如 `file`）一律略過。
pub fn parse_cbom(json: &str) -> Result<Vec<CryptoAsset>> {
    let doc: CbomDoc =
        serde_json::from_str(json).map_err(|e| CytraceError::Parse(format!("cbom: {e}")))?;

    // 先建 bom-ref → (名稱, 曲線, NIST 等級) 索引：憑證的量子狀態由其
    // signatureAlgorithmRef / subjectPublicKeyRef 指向的元件決定，而非憑證的 subject 名稱。
    let components_for_index = doc.components.clone().unwrap_or_default();
    let index: std::collections::HashMap<&str, (&str, Option<&str>, Option<u8>)> =
        components_for_index
            .iter()
            .filter_map(|c| {
                let r = c.bom_ref.as_deref()?;
                let alg = c.crypto_properties.as_ref()?.algorithm.as_ref();
                Some((
                    r,
                    (
                        c.name.as_str(),
                        alg.and_then(|a| a.curve.as_deref()),
                        alg.and_then(|a| a.nist_level),
                    ),
                ))
            })
            .collect();

    let components = doc.components.unwrap_or_default();
    Ok(components
        .iter()
        .filter(|c| c.kind == "cryptographic-asset")
        .filter_map(|c| {
            let props = c.crypto_properties.as_ref()?;
            let alg = props.algorithm.as_ref();
            let curve = alg.and_then(|a| a.curve.as_deref());
            let key_size = props.material.as_ref().and_then(|m| m.size);

            // 憑證：改以所引用之演算法判定（ADR-013 決策 6）；引用缺席或指不到才退回自身名稱
            let referenced = props
                .certificate
                .as_ref()
                .and_then(|cert| {
                    cert.signature_algorithm_ref
                        .as_deref()
                        .or(cert.subject_public_key_ref.as_deref())
                })
                .and_then(|r| index.get(r).copied());
            let (q_name, q_curve, q_level) = match referenced {
                Some((n, cv, lv)) => (n, cv, lv),
                None => (c.name.as_str(), curve, alg.and_then(|a| a.nist_level)),
            };

            let quantum = quantum::classify_with_level(q_name, q_curve, q_level);
            Some(CryptoAsset {
                quantum,
                weak_key: quantum::weak_key(&c.name, curve, key_size),
                name: c.name.clone(),
                asset_type: props.asset_type.clone(),
                location: c
                    .evidence
                    .as_ref()
                    .and_then(|e| e.occurrences.first())
                    .map(|o| o.location.clone())
                    .unwrap_or_default(),
                primitive: alg
                    .and_then(|a| a.primitive.clone())
                    .or_else(|| props.material.as_ref().and_then(|m| m.kind.clone())),
                key_size,
                not_after: props
                    .certificate
                    .as_ref()
                    .and_then(|c| c.not_valid_after.clone()),
            })
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    const GRYPE_SAMPLE: &str = r#"{
      "matches": [
        {
          "vulnerability": {
            "id": "CVE-2024-0001",
            "severity": "High",
            "dataSource": "https://nvd.nist.gov/vuln/detail/CVE-2024-0001",
            "fix": { "versions": ["1.1.1w"], "state": "fixed" },
            "cvss": [ { "metrics": { "baseScore": 7.5 } } ]
          },
          "artifact": { "name": "openssl", "version": "1.1.1k", "type": "deb" }
        },
        {
          "vulnerability": {
            "id": "CVE-2024-0002",
            "severity": "negligible",
            "dataSource": "ghsa",
            "cvss": []
          },
          "artifact": { "name": "zlib", "version": "1.2.11", "type": "deb" }
        }
      ],
      "descriptor": { "name": "grype", "version": "0.74.0" }
    }"#;

    #[test]
    fn parses_grype_matches_into_vulnerabilities() {
        let v = parse_grype(GRYPE_SAMPLE).unwrap();
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].id, "CVE-2024-0001");
        assert_eq!(v[0].severity, Severity::High);
        assert_eq!(v[0].cvss, Some(7.5));
        assert_eq!(v[0].component, "openssl");
        assert_eq!(v[0].fixed_version.as_deref(), Some("1.1.1w"));
        assert_eq!(v[1].severity, Severity::Negligible);
        assert_eq!(v[1].cvss, None);
        assert_eq!(v[1].fixed_version, None);
    }

    #[test]
    fn grype_empty_matches_yields_empty() {
        assert!(parse_grype(r#"{"matches":[]}"#).unwrap().is_empty());
    }

    #[test]
    fn malformed_grype_json_is_parse_error() {
        let err = parse_grype("not json").unwrap_err();
        assert!(matches!(err, CytraceError::Parse(_)));
    }

    const CYCLONEDX_SAMPLE: &str = r#"{
      "bomFormat": "CycloneDX",
      "specVersion": "1.5",
      "components": [
        {
          "type": "library",
          "name": "openssl",
          "version": "1.1.1k",
          "licenses": [ { "license": { "id": "Apache-2.0" } } ]
        },
        {
          "type": "library",
          "name": "mit-lib",
          "version": "2.0.0",
          "licenses": [ { "expression": "MIT OR Apache-2.0" } ]
        }
      ]
    }"#;

    #[test]
    fn parses_cyclonedx_components_with_licenses() {
        let c = parse_cyclonedx(CYCLONEDX_SAMPLE).unwrap();
        assert_eq!(c.len(), 2);
        assert_eq!(c[0].name, "openssl");
        assert_eq!(c[0].kind, "library");
        assert_eq!(c[0].licenses, vec!["Apache-2.0".to_string()]);
        assert_eq!(c[1].licenses, vec!["MIT OR Apache-2.0".to_string()]);
    }
}
