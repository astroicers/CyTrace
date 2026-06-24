//! 解析 Grype JSON 與 CycloneDX SBOM → 統一型別（FR-003 / SDS §4）。
//!
//! 只擷取需要的欄位，其餘以 `#[serde(default)]` 容忍，避免上游 schema 微調即失敗。

use crate::error::{CytraceError, Result};
use cytrace_types::{Component, Severity, Vulnerability};
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
