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
    id: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    version: String,
    #[serde(default)]
    purl: String,
    #[serde(default)]
    locations: Vec<GrypeLocation>,
}

#[derive(Deserialize)]
struct GrypeLocation {
    #[serde(default)]
    path: String,
}

/// 空字串視同沒有（避免輸出 `"purl": ""` 這類假值）。
fn non_empty(s: String) -> Option<String> {
    (!s.is_empty()).then_some(s)
}

/// purl 的比對鍵：percent-decode（`%40` → `@`）。同一套件在 Syft 與 Grype 的序列化可能編碼不同；
/// 不合法的 `%` 序列原樣保留。只用於比對，不改寫輸出的 purl。
fn purl_key(purl: &str) -> String {
    fn hex(c: u8) -> Option<u8> {
        (c as char).to_digit(16).map(|d| d as u8)
    }
    let b = purl.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2])) {
                out.push(h << 4 | l);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|_| purl.to_string())
}

/// 依序合併多個元件的位置，去除重複、保留先後。
fn union_locations<'a>(comps: impl Iterator<Item = &'a Component>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for loc in comps.flat_map(|c| c.locations.iter()) {
        if !out.contains(loc) {
            out.push(loc.clone());
        }
    }
    out
}

/// 弱點 → 元件位置的對應（ADR-009「修訂：schema v3」）：
/// Grype 自帶位置 → `artifact.id` 等於元件 `bom_ref`（命中即停）→ 同 purl 聯集（artifact 有 purl 時到此為止）
/// → artifact 沒有 purl 時才以同名稱＋版本聯集 → 留空。
fn resolve_locations(a: &GrypeArtifact, components: &[Component]) -> Vec<String> {
    let mut own: Vec<String> = Vec::new();
    for p in a
        .locations
        .iter()
        .map(|l| &l.path)
        .filter(|p| !p.is_empty())
    {
        if !own.contains(p) {
            own.push(p.clone());
        }
    }
    if !own.is_empty() {
        return own;
    }
    // id 精確命中某元件就停在這裡：該元件沒有位置時留空，不退到 purl 聯集
    // ——那會把同 purl 的其他實例位置掛到這筆弱點上，是猜測
    if !a.id.is_empty() {
        let hits: Vec<&Component> = components
            .iter()
            .filter(|c| c.bom_ref.as_deref() == Some(a.id.as_str()))
            .collect();
        if !hits.is_empty() {
            return union_locations(hits.into_iter());
        }
    }
    // 有 purl 就以 purl 為準，對不到也不退到名稱＋版本：同名同版的套件可能屬於別的生態系
    // （npm 與 PyPI 都有 lodash），混進來就是猜測
    if !a.purl.is_empty() {
        let key = purl_key(&a.purl);
        return union_locations(
            components
                .iter()
                .filter(|c| c.purl.as_deref().map(purl_key).as_deref() == Some(key.as_str())),
        );
    }
    union_locations(
        components
            .iter()
            .filter(|c| c.name == a.name && c.version == a.version),
    )
}

/// 解析 Grype JSON 輸出為弱點清單（不對應元件位置；位置只取 Grype 自帶的）。
pub fn parse_grype(json: &str) -> Result<Vec<Vulnerability>> {
    parse_grype_for(json, &[])
}

/// 解析 Grype JSON，並以同一次掃描的元件清單對應每筆弱點的所在位置（見 [`resolve_locations`]）。
pub fn parse_grype_for(json: &str, components: &[Component]) -> Result<Vec<Vulnerability>> {
    let doc: GrypeDoc =
        serde_json::from_str(json).map_err(|e| CytraceError::Parse(format!("grype: {e}")))?;
    Ok(doc
        .matches
        .into_iter()
        .map(|m| {
            let locations = resolve_locations(&m.artifact, components);
            Vulnerability {
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
                component_version: non_empty(m.artifact.version),
                component_purl: non_empty(m.artifact.purl),
                locations,
            }
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
    #[serde(default, rename = "bom-ref")]
    bom_ref: String,
    #[serde(default)]
    purl: String,
    #[serde(default)]
    properties: Vec<CycloneProperty>,
}

#[derive(Deserialize)]
struct CycloneProperty {
    #[serde(default)]
    name: String,
    #[serde(default)]
    value: String,
}

/// Syft 的位置屬性 `syft:location:<N>:path` → 依 N 排序的路徑（索引不是數字的忽略）。
fn syft_locations(props: &[CycloneProperty]) -> Vec<String> {
    let mut indexed: Vec<(u32, String)> = props
        .iter()
        .filter_map(|p| {
            let n = p
                .name
                .strip_prefix("syft:location:")?
                .strip_suffix(":path")?;
            Some((n.parse().ok()?, p.value.clone()))
        })
        .filter(|(_, v)| !v.is_empty())
        .collect();
    indexed.sort_by_key(|(n, _)| *n);
    indexed.into_iter().map(|(_, v)| v).collect()
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
        // Syft 的 file 類元件以主機絕對路徑為名、無版本與 purl、不參與比對：不進 ScanResult（T928，ADR-009 修訂）
        .filter(|c| c.kind != "file")
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
                locations: syft_locations(&c.properties),
                bom_ref: non_empty(c.bom_ref),
                purl: non_empty(c.purl),
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

    // ── T925：來源欄位（ADR-009 修訂：schema v3）──

    /// Syft 的真實形狀：bom-ref、purl、`syft:location:N:path`（夾雜其他屬性、順序打亂、索引不連號）。
    const CYCLONEDX_WITH_PROVENANCE: &str = r#"{
      "components": [
        {
          "bom-ref": "pkg:npm/lodash@4.17.20?package-id=aaaa",
          "type": "library", "name": "lodash", "version": "4.17.20",
          "purl": "pkg:npm/lodash@4.17.20",
          "properties": [
            { "name": "syft:package:foundBy", "value": "javascript-lock-cataloger" },
            { "name": "syft:location:2:path", "value": "/c/package-lock.json" },
            { "name": "syft:location:0:path", "value": "/a/package-lock.json" },
            { "name": "syft:location:x:path", "value": "/ignored" },
            { "name": "syft:location:0:layerID", "value": "sha256:zz" }
          ]
        },
        { "type": "library", "name": "bare", "version": "1.0.0" },
        { "type": "library", "name": "emptypurl", "version": "1", "purl": "", "bom-ref": "" }
      ]
    }"#;

    #[test]
    fn cyclonedx_provenance_is_read_and_locations_are_ordered_by_index() {
        let c = parse_cyclonedx(CYCLONEDX_WITH_PROVENANCE).unwrap();
        assert_eq!(
            c[0].bom_ref.as_deref(),
            Some("pkg:npm/lodash@4.17.20?package-id=aaaa")
        );
        assert_eq!(c[0].purl.as_deref(), Some("pkg:npm/lodash@4.17.20"));
        // 依 N 排序；非數字索引與非 path 屬性不算
        assert_eq!(
            c[0].locations,
            ["/a/package-lock.json", "/c/package-lock.json"]
        );
        // 沒有來源資訊的元件：欄位為空，不報錯
        assert_eq!(c[1].bom_ref, None);
        assert_eq!(c[1].purl, None);
        assert!(c[1].locations.is_empty());
        // 空字串視同沒有（不輸出 "purl": ""）
        assert_eq!(c[2].purl, None);
        assert_eq!(c[2].bom_ref, None);
    }

    fn comp(
        bom_ref: &str,
        name: &str,
        version: &str,
        purl: Option<&str>,
        locs: &[&str],
    ) -> Component {
        Component {
            name: name.into(),
            version: version.into(),
            kind: "library".into(),
            licenses: vec![],
            bom_ref: Some(bom_ref.into()),
            purl: purl.map(Into::into),
            locations: locs.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn grype_one(artifact: &str) -> String {
        format!(
            r#"{{"matches":[{{"vulnerability":{{"id":"CVE-1","severity":"High","dataSource":"https://x"}},
                "artifact":{artifact}}}]}}"#
        )
    }

    /// 兩份 lockfile 各有一個 lodash 4.17.20（同 purl、不同 bom-ref），另有不同版本的 lodash。
    fn components() -> Vec<Component> {
        vec![
            comp(
                "ref-a",
                "lodash",
                "4.17.20",
                Some("pkg:npm/lodash@4.17.20"),
                &["/a/package-lock.json"],
            ),
            comp(
                "ref-b",
                "lodash",
                "4.17.20",
                Some("pkg:npm/lodash@4.17.20"),
                &["/b/package-lock.json"],
            ),
            comp(
                "ref-c",
                "lodash",
                "4.17.21",
                Some("pkg:npm/lodash@4.17.21"),
                &["/c/package-lock.json"],
            ),
            comp("ref-d", "nopurl", "2.0", None, &["/d/requirements.txt"]),
            // 同名同版、不同生態系：名稱＋版本對得上，purl 對不上
            comp(
                "ref-e",
                "lodash",
                "4.17.20",
                Some("pkg:pypi/lodash@4.17.20"),
                &["/py/requirements.txt"],
            ),
        ]
    }

    #[test]
    fn grype_artifact_version_and_purl_are_kept() {
        let v = parse_grype_for(
            &grype_one(r#"{"name":"lodash","version":"4.17.20","purl":"pkg:npm/lodash@4.17.20"}"#),
            &[],
        )
        .unwrap();
        assert_eq!(v[0].component, "lodash");
        assert_eq!(v[0].component_version.as_deref(), Some("4.17.20"));
        assert_eq!(
            v[0].component_purl.as_deref(),
            Some("pkg:npm/lodash@4.17.20")
        );
        // 空字串視同沒有
        let v = parse_grype_for(&grype_one(r#"{"name":"x","version":"","purl":""}"#), &[]).unwrap();
        assert_eq!(v[0].component_version, None);
        assert_eq!(v[0].component_purl, None);
    }

    /// 對應鏈第 1 段：Grype 自帶位置就直接採用（即使元件清單也對得到）。
    #[test]
    fn link_prefers_grype_artifact_locations() {
        let v = parse_grype_for(
            &grype_one(
                r#"{"id":"ref-a","name":"lodash","version":"4.17.20","purl":"pkg:npm/lodash@4.17.20",
                    "locations":[{"path":"/from/grype.json"}]}"#,
            ),
            &components(),
        )
        .unwrap();
        assert_eq!(v[0].locations, ["/from/grype.json"]);
    }

    /// 第 2 段：artifact.id 等於元件 bom-ref → 只取那一個元件的位置（不混入同 purl 的另一份）。
    #[test]
    fn link_by_bom_ref_is_exact() {
        let v = parse_grype_for(
            &grype_one(r#"{"id":"ref-b","name":"lodash","version":"4.17.20","purl":"pkg:npm/lodash@4.17.20"}"#),
            &components(),
        )
        .unwrap();
        assert_eq!(v[0].locations, ["/b/package-lock.json"]);
    }

    /// 第 2 段精確命中、但該元件沒有位置 → 停在這裡留空，不退到 purl 聯集：
    /// 那會把同 purl 的「兄弟實例」位置掛到這筆弱點上，是猜測（複審 finding）。
    #[test]
    fn exact_bom_ref_hit_without_locations_stays_empty() {
        let comps = vec![
            comp(
                "ref-x",
                "lodash",
                "4.17.20",
                Some("pkg:npm/lodash@4.17.20"),
                &[],
            ),
            comp(
                "ref-y",
                "lodash",
                "4.17.20",
                Some("pkg:npm/lodash@4.17.20"),
                &["/y/package-lock.json"],
            ),
        ];
        let v = parse_grype_for(
            &grype_one(r#"{"id":"ref-x","name":"lodash","version":"4.17.20","purl":"pkg:npm/lodash@4.17.20"}"#),
            &comps,
        )
        .unwrap();
        assert!(v[0].locations.is_empty(), "{:?}", v[0].locations);
    }

    /// Grype 自帶的空字串路徑不算位置（會被濾掉，再往下走對應鏈）。
    #[test]
    fn empty_grype_location_paths_are_ignored() {
        let v = parse_grype_for(
            &grype_one(r#"{"id":"ref-b","name":"lodash","version":"4.17.20","purl":"pkg:npm/lodash@4.17.20","locations":[{"path":""}]}"#),
            &components(),
        )
        .unwrap();
        assert_eq!(v[0].locations, ["/b/package-lock.json"]);
    }

    /// 第 3 段：沒有可用的 id → 同 purl 的所有元件位置聯集；不同版本（4.17.21）不得混入。
    #[test]
    fn link_by_purl_unions_all_instances() {
        let v = parse_grype_for(
            &grype_one(r#"{"id":"unknown","name":"lodash","version":"4.17.20","purl":"pkg:npm/lodash@4.17.20"}"#),
            &components(),
        )
        .unwrap();
        assert_eq!(
            v[0].locations,
            ["/a/package-lock.json", "/b/package-lock.json"]
        );
    }

    /// purl 比對不受百分比編碼影響：Syft 把 scoped npm 套件寫成 `%40babel`，Grype 重新序列化時
    /// 可能寫成 `@babel`（反之亦然）。逐字比對會對不到，而帶 purl 時又不退到名稱＋版本，位置會靜默變空。
    #[test]
    fn purl_match_ignores_percent_encoding() {
        let comps = vec![
            comp(
                "ref-x",
                "@babel/code-frame",
                "7.29.7",
                Some("pkg:npm/%40babel/code-frame@7.29.7"),
                &["/package-lock.json"],
            ),
            comp(
                "ref-y",
                "@babel/core",
                "7.29.7",
                Some("pkg:npm/%40babel/core@7.29.7"),
                &["/other/package-lock.json"],
            ),
        ];
        let v = parse_grype_for(
            &grype_one(r#"{"name":"@babel/code-frame","version":"7.29.7","purl":"pkg:npm/@babel/code-frame@7.29.7"}"#),
            &comps,
        )
        .unwrap();
        assert_eq!(
            v[0].locations,
            ["/package-lock.json"],
            "編碼不同、同一套件須對得上，且不得混入其他套件"
        );

        // 反方向：元件未編碼、artifact 編碼
        let comps = vec![comp(
            "ref-z",
            "@a/b",
            "1.0.0",
            Some("pkg:npm/@a/b@1.0.0"),
            &["/x/package-lock.json"],
        )];
        let v = parse_grype_for(
            &grype_one(r#"{"name":"@a/b","version":"1.0.0","purl":"pkg:npm/%40a/b@1.0.0"}"#),
            &comps,
        )
        .unwrap();
        assert_eq!(v[0].locations, ["/x/package-lock.json"]);
    }

    #[test]
    fn purl_key_decodes_valid_escapes_and_keeps_the_rest() {
        assert_eq!(purl_key("pkg:npm/%40a/b@1"), "pkg:npm/@a/b@1");
        assert_eq!(
            purl_key("pkg:npm/%4"),
            "pkg:npm/%4",
            "結尾不完整的序列原樣保留"
        );
        assert_eq!(purl_key("pkg:x/%zz@1"), "pkg:x/%zz@1", "非十六進位原樣保留");
        assert_eq!(purl_key("pkg:x/é%40"), "pkg:x/é@", "多位元組字元不得被切壞");
        assert_eq!(purl_key(""), "");
        // decode 後不是合法 UTF-8 → 退回原字串（比對仍以原字串進行，不 panic）
        assert_eq!(purl_key("pkg:x/%ff@1"), "pkg:x/%ff@1");
    }

    /// artifact 帶 purl 卻對不到任何元件 → 不得退到名稱＋版本：那會把其他生態系的同名套件混進來。
    #[test]
    fn purl_mismatch_does_not_fall_back_to_name_and_version() {
        let v = parse_grype_for(
            &grype_one(r#"{"name":"lodash","version":"4.17.20","purl":"pkg:gem/lodash@4.17.20"}"#),
            &components(),
        )
        .unwrap();
        assert!(v[0].locations.is_empty(), "{:?}", v[0].locations);
    }

    /// 第 4 段：沒有 purl → 以名稱＋版本對應。
    #[test]
    fn link_by_name_and_version_when_no_purl() {
        let v = parse_grype_for(
            &grype_one(r#"{"name":"nopurl","version":"2.0"}"#),
            &components(),
        )
        .unwrap();
        assert_eq!(v[0].locations, ["/d/requirements.txt"]);
    }

    /// 第 5 段：都對不到 → 留空，不猜測（名稱相同但版本不同也不算）。
    #[test]
    fn link_leaves_locations_empty_when_nothing_matches() {
        let v = parse_grype_for(
            &grype_one(r#"{"name":"lodash","version":"9.9.9"}"#),
            &components(),
        )
        .unwrap();
        assert!(v[0].locations.is_empty());
    }

    /// T928：Syft 把被讀過的檔案列成 `type:"file"` 元件，名稱是主機絕對路徑（Web 模式下會露出
    /// `<資料目錄>/jobs/<id>/input/…`）、沒有版本與 purl、不參與弱點比對——不進 ScanResult 與報表
    /// （ADR-009 修訂，使用者 2026-10-07 裁定）。其他類型（含 operating-system）照收；原始 sbom.cdx.json 不受影響。
    #[test]
    fn syft_file_components_are_excluded() {
        let c = parse_cyclonedx(
            r#"{ "components": [
              { "bom-ref": "a1", "type": "library", "name": "requests", "version": "2.19.0",
                "purl": "pkg:pypi/requests@2.19.0" },
              { "bom-ref": "f1", "type": "file", "name": "/srv/cytrace/jobs/x/input/extracted/requirements.txt",
                "hashes": [ { "alg": "SHA-1", "content": "0000000000000000000000000000000000000000" } ] },
              { "bom-ref": "o1", "type": "operating-system", "name": "alpine", "version": "3.22.1" }
            ] }"#,
        )
        .unwrap();
        let kinds: Vec<(&str, &str)> = c
            .iter()
            .map(|x| (x.kind.as_str(), x.name.as_str()))
            .collect();
        assert_eq!(
            kinds,
            [("library", "requests"), ("operating-system", "alpine")]
        );
    }

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
