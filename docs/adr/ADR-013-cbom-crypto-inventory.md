# [ADR-013]: CBOM 密碼學資產盤點（CycloneDX CBOM + cbomkit-theia 第三引擎）

| 欄位 | 內容 |
|------|------|
| **狀態** | `Draft` |
| **日期** | 2026-09-22 |
| **決策者** | CyTrace Team |

> **狀態說明：** `Draft`（初稿，禁止實作）→ `FIRM`（POC 驗證，允許 commit，需附驗證證據）→ `Accepted`（人類審核通過）

---

## 背景（Context）

交件方除了「依賴有哪些 CVE」，開始要求盤點「系統裡有哪些密碼學資產、哪些在後量子時代會失效」。
CycloneDX 自 **1.6**（2024-04）起以 `type: "cryptographic-asset"` + `cryptoProperties` 定義
**CBOM**（Cryptography Bill of Materials），**1.7**（2025-10）再加 Cryptography Registry 封閉清單。

**現況（2026-09-22 實查）：**
- CyTrace 無任何 crypto / CBOM 實作；SBOM 由 Syft 產出後原樣落地（`engine.rs` → `sbom.cdx.json`），
  `parse_cyclonedx` 只取 name/version/type/licenses。
- 現行引擎 **Syft v1.52 不產 CBOM**（僅以 binary classifier 把 openssl/aws-lc 認成套件）；
  **Grype** 無此能力；**Trivy** 的 CycloneDX CBOM 輸出（PR #11125）尚未合併。
- 後量子背景：NIST FIPS 203/204/205（ML-KEM / ML-DSA / SLH-DSA）已定案；
  **NIST IR 8547 仍為初稿（2024-11 ipd）**，2030 棄用 112-bit 量子脆弱演算法、2035 全面禁用為「提議」日期；
  NSA CNSA 2.0 已公布演算法清單。

## 評估選項（Options Considered）

### 選項 A：cbomkit-theia 作第三引擎（採用）
- PQCA（Linux Foundation）維護，原 IBM 捐出；Go、**Apache-2.0**；v1.1.2（2026-05）且持續提交。
- 上游 Dockerfile 以 `CGO_ENABLED=0` 建置 → 靜態 binary；非測試原始碼無硬編碼外連 URL，
  **僅在給 registry 參照時才走網路**；`dir <path>`、docker-save tar、OCI layout 皆可離線。
- 偵測：X.509 憑證（簽章/公鑰演算法）、公私鑰與密鑰（內嵌 gitleaks 規則）、`openssl.cnf`（TLS 版本/cipher suite）、
  `java.security`（disabledAlgorithms 信心值）。輸出 CycloneDX **1.6 JSON**（stdout）。
- **缺點**：依賴樹大（containerd、moby、gitleaks、wazero、各式 archive 函式庫）；不掃原始碼；
  Windows 建置未經驗證。

### 選項 B：自建 Rust 憑證掃描（`x509-parser`）
- 零新 binary、供應鏈最乾淨；但只涵蓋憑證/公鑰，TLS/JCA 設定、金鑰偵測需自行重寫，工作量大。
- **保留為備案**：若選項 A 供應鏈審查不通過或 Windows 無法建置，改走此路。

### 選項 C：cdxgen（`--include-crypto`）
- Apache-2.0、可產 1.7；但 standalone 體積大、多數語言會觸發套件管理器外連（需 secure mode 才收斂）→
  違反「穩定優先」與零外連原則。否決。

### 選項 D：sonar-cryptography / cbomkit 後端
- 原始碼層演算法偵測最完整，但需 SonarQube + JVM（或 Quarkus + Postgres）→ 無法單包離線交付。否決。

### 選項 E：等 Syft / Trivy 上游
- 不增加引擎；但時程不可控。**列為長期觀察**：上游正式支援後可再評估收斂回 Syft。

## 決策（Decision）

1. **引擎**：採選項 A，釘選 **cbomkit-theia** 為第三引擎，版本與 SHA256 寫入 `scripts/versions.env`；
   **自源碼 `go mod vendor` 建置**（不依賴上游 release binary），產物 checksum 釘死。
2. **輸入限制**：`RealEngine` 只允許 `dir <本地路徑>` 與 `image <docker-save tar / OCI layout>`；
   **拒絕 registry 參照**（防止觸發外連）。
3. **範圍**：第一階段只盤點**檔案系統 / 映像層**密碼資產（憑證、金鑰、TLS/JCA 設定）。
   **原始碼層演算法使用偵測列為範圍外**（無符合單包離線的方案），報表需明示此限制。
4. **預設關閉**：CLI `run` / `scan` / `batch` 以 `--cbom` 開啟；console 以勾選項開啟。引擎缺席時降級，
   CBOM 區段標「未執行」，**不影響 SBOM / CVE 流程與 exit code**。
5. **輸出物**：`scan` 多落地 `cbom.cdx.json`（theia 原樣輸出，與 `sbom.cdx.json` 同策略，不自行改寫升版）；
   解析端容忍 CycloneDX 1.6 / 1.7 子集。
6. **量子脆弱判定**（Rust core 新模組 `quantum.rs`）：
   - 移植 cbomkit `opa/quantum_safe.rego`（Apache-2.0）規則：PQC 名稱 / OID 白名單
     （ML-KEM、ML-DSA、SLH-DSA、Falcon、XMSS、LMS…）、`nistQuantumSecurityLevel` 門檻、對稱演算法 → 不適用；
   - 補金鑰長度規則：RSA < 2048、ECC < 256 bit → 弱金鑰；
   - 輸出 `Safe / Vulnerable / NotApplicable / Unknown`；**不做 CNSA 2.0 逐項對照**（留待後續）。
   - 報表中 NIST IR 8547 年限一律標示「草案」。
7. **資料契約（修訂 ADR-009）**：`ScanResult` 新增 `crypto: Option<CryptoInventory>`（`#[serde(default)]`），
   `SCHEMA_VERSION` 1 → 2；v1 檔以 `report` 子命令仍可重建。
8. **信任邊界（NFR-09）**：`ScanResult` 與報表只可記錄私鑰「存在、型別、長度、指紋、路徑」，
   **絕不含金鑰內容**；以含假私鑰 fixture 的測試斷言把關。
9. **可選閘門**：`--fail-on-quantum-vulnerable`（exit code 2，沿用 `failon.rs` 模式），預設不啟用。

## 供應鏈審查（核准前必須完成）

本專案鐵則禁止中國來源依賴。theia 依賴樹需逐模組審查原產地與授權，審查結果附於本節：

| 項目 | 狀態 |
|------|------|
| `go list -m all` 全清單 + 授權彙整 | ⏳ 待做 |
| 間接依賴 `huandu/xstrings`（經 Masterminds/sprig）原產地判定 | ⏳ 待做（若不合規 → fork 剔除 sprig 或改選項 B） |
| 內嵌 gitleaks 規則庫授權（MIT）確認 | ⏳ 待做 |
| `GOOS=windows` 建置 + `dir` 模式實測（ADR-010） | ⏳ 待做 |
| 假私鑰 fixture：確認 theia 輸出不含金鑰內容 | ⏳ 待做 |

## 後果（Consequences）

**正面影響：**
- 交件新增 CBOM，可回應後量子遷移盤點需求；沿用既有單檔報表與離線交付鏈。
- 引擎選自中立基金會（PQCA / LF）、Apache-2.0，與 Syft/Grype 同授權。

**負面影響 / 技術債：**
- 第三個 Go binary：離線包與 image 體積增加（預估數十 MB），版本 bump 與驗證多一條線。
- theia 自源碼建置需 Go toolchain 進建置環境（Dockerfile 新增 go builder stage）。
- 範圍不含原始碼演算法偵測；使用者若誤以為「CBOM 全覆蓋」會高估安全性 → 報表 Notes 區需明示。
- 量子判定規則為名稱 / OID 對照，準確度受 theia 偵測品質限制。

**後續追蹤：**
- 觀察 Syft / Trivy 上游 CBOM 支援，成熟後評估收斂。
- CNSA 2.0 逐項對照、NIST IR 8547 定稿後更新年限文案。

## 成功指標（Success Metrics）

| 指標 | 目標值 | 驗證方式 | 檢查時間 |
|------|--------|----------|----------|
| 零外連 | `--network none` 下 `run --cbom` 成功 | 離線 E2E | 每次 release |
| 私鑰不外洩 | 報表 / ScanResult / 日誌不含 fixture 金鑰內容 | 單元測試斷言 | 每次 CI |
| v1 相容 | v1 ScanResult 以 `report` 可重建 | 回歸測試 | 每次 CI |
| golden 穩定 | CBOM fixture golden 不變 | `tests/golden` | 每次 CI |
| 降級不影響主流程 | theia 缺席時 SBOM/CVE 報表正常、exit code 不變 | 整合測試 | 每次 CI |

## 關聯（Relations）

- 修訂：ADR-009（ScanResult schema v2）
- 沿用：ADR-002（引擎選型原則、禁中國來源）、ADR-005（單檔報表）、ADR-007 / ADR-010 / ADR-012（交付鏈、雙平台、容器）、ADR-004（i18n）
- 參考：ROADMAP M9（T901–T907）；`.asp-fact-check.md`
