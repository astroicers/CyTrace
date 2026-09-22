# [ADR-013]: CBOM 密碼學資產盤點（CycloneDX CBOM + cbomkit-theia 第三引擎）

| 欄位 | 內容 |
|------|------|
| **狀態** | `Draft` |
| **接受日期** | —（未接受；升 `Accepted` 僅限人類 `/asp:approve-adr`） |
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
- 現行引擎 **Syft 不產 CBOM**——釘選版 1.45.1（`scripts/versions.env:5`）與上游最新 1.52 皆然
  （僅以 binary classifier 把 openssl/aws-lc 認成套件）；
  **Grype** 無此能力；**Trivy** 的 CycloneDX CBOM 輸出（PR #11125）尚未合併。
- 後量子背景：NIST FIPS 203/204/205（ML-KEM / ML-DSA / SLH-DSA）已定案；
  **NIST IR 8547 仍為初稿（2024-11 ipd）**，2030 棄用 112-bit 量子脆弱演算法、2035 全面禁用為「提議」日期；
  NSA CNSA 2.0 已公布演算法清單。

## 評估選項（Options Considered）

### 選項 A：cbomkit-theia 作第三引擎（採用）
- PQCA（Linux Foundation）維護，原 IBM 捐出；Go、**專案本體 Apache-2.0**（惟**內嵌的 gitleaks 規則庫為 MIT**
  ——故「交件全為 Apache-2.0」不再成立，見下方「修訂提議」）；v1.1.2（2026-05）且持續提交。
- `[UNVERIFIED]` 上游 Dockerfile 以 `CGO_ENABLED=0` 建置 → 靜態 binary；非測試原始碼無硬編碼外連 URL，
  **僅在給 registry 參照時才走網路**；`dir <path>`、docker-save tar、OCI layout 皆可離線。
  —— 以上為**讀原始碼推論**，且讀的是 `main@1571014` 非釘選的 `v1.1.2`，未實建、未於 `--network none` 實測；
  查證依據見 `.asp-gate-log/20260922T075351Z-factcheck-ADR-013.md`，實測列於 ROADMAP **T901b**。
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

1. **引擎**：採選項 A，釘選 **cbomkit-theia** 為第三引擎，版本寫入 `scripts/versions.env`；
   **自源碼 `go mod vendor` 建置**（不依賴上游 release binary）。
   **可重現建置條件**（與 syft/grype 釘上游 release tar 的 SHA 本質不同，必須明列）：
   - 釘 Go toolchain 版本（與上游 go.mod 一致，寫入 `versions.env`）；
   - 建置旗標固定 `CGO_ENABLED=0 GOFLAGS=-mod=vendor go build -trimpath -buildvcs=false -ldflags="-s -w -buildid="`；
   - **釘死的是 vendored 原始碼 tarball 的 SHA256 + `go.sum`**；binary SHA256 為建置產物紀錄，
     由 CI 產生並隨交付附上（Dockerfile / `package.sh` / `package.ps1` 三處共用同一組參數，
     不同平台的 binary SHA 本就不同，不得互相比對）。
2. **輸入限制**：**限制實作於 `engine::cbom` 自由函式層**（非僅 `RealEngine`——CLI 走
   `engine::sbom` / `engine::vuln` 自由函式，不經 `RealEngine`，見 `crates/cytrace-cli/src/main.rs:126`）：
   只允許 `dir <本地路徑>` 與 `image <docker-save tar / OCI layout>`，**拒絕 registry 參照**（防止觸發外連）。
   **目標字串轉譯規則**：CyTrace 目標語法沿用 syft（`dir:`、`docker-archive:`、單檔路徑、裸映像名）；
   轉譯時 —— 既有目錄 → `dir`；既有 tar / OCI layout 目錄 → `image`；
   **裸映像名或任何無法在本地判定的形態 → 拒絕（回報 i18n 錯誤鍵，不猜測）**。
3. **範圍**：第一階段只盤點**檔案系統 / 映像層**密碼資產（憑證、金鑰、TLS/JCA 設定）。
   **原始碼層演算法使用偵測列為範圍外**（無符合單包離線的方案），報表需明示此限制。
4. **預設關閉與降級語意**：CLI `run` / `scan` / `batch` 以 `--cbom` 開啟；console 以勾選項開啟。
   現行 `CytraceError::Engine`（`crates/cytrace-core/src/error.rs:9`）把「binary 不存在」與「子程序失敗」
   併為同一型別，且 CLI 以 `?` 直接中止、server 把整個 job 標 Failed —— **沿用它做不到降級**，故新設計：
   - `engine::cbom` 回傳 `Result<Option<String>>`：**binary 不存在（`io::ErrorKind::NotFound`）→ `Ok(None)`**；
   - **其餘失敗（子程序非零、輸出非 JSON、解析失敗）→ `Err`，且不得中止 SBOM/CVE 主流程**：
     於呼叫端捕捉，記為 `CbomStatus::Failed { reason_key }`；
   - 三種「無 CBOM」狀態在資料契約中必須可區分（見決策 7）：`NotRequested` / `EngineAbsent` / `Failed`。
   - 主流程 exit code 不受影響 —— **唯一例外見決策 9**。
5. **輸出物**：`scan` 多落地 `cbom.cdx.json`（theia 原樣輸出，與 `sbom.cdx.json` 同策略，不自行改寫升版）；
   解析端容忍 CycloneDX 1.6 / 1.7 子集。
   **落地前必經決策 8 的私鑰檢查**：若 theia 輸出含金鑰內容，依決策 8 處置（不得原樣落地）。
6. **量子脆弱判定**（Rust core 新模組 `quantum.rs`）：
   - 移植 cbomkit `opa/quantum_safe.rego`（Apache-2.0）規則：PQC 名稱 / OID 白名單
     （ML-KEM、ML-DSA、SLH-DSA、Falcon、XMSS、LMS…）、`nistQuantumSecurityLevel` 門檻、對稱演算法 → 不適用；
   - **量子狀態與弱金鑰是兩條獨立的軸**，不得混為一值：
     `quantum: Safe / Vulnerable / NotApplicable / Unknown` 與 `weak_key: bool`（附判定依據）分欄輸出
     （RSA-4096 為 `Vulnerable` 但非 `weak_key`；RSA < 2048、ECC 曲線強度 < 128-bit 安全等級 → `weak_key`）。
   - **ECC 依曲線名稱判定，不以位元數門檻判定**（Ed25519 / X25519 常報 255 bit，位元數門檻會誤判為弱金鑰）；
     曲線名稱對照表列於實作，未知曲線 → `Unknown`，不臆測。
   - 輸出 `Safe / Vulnerable / NotApplicable / Unknown`；**不做 CNSA 2.0 逐項對照**（留待後續）。
   - 報表中 NIST IR 8547 年限一律標示「草案」。
7. **資料契約（修訂 ADR-009）**：`ScanResult` 新增 `crypto: Option<CryptoInventory>`，
   `CryptoInventory` 內含 `status: CbomStatus`（`NotRequested` / `EngineAbsent` / `Failed` / `Completed`），
   故「CBOM 有跑但 0 資產」與「未執行」可區分。`SCHEMA_VERSION` 1 → 2。
   - **所有新增欄位（含 `Summary` 的 crypto 計數、`ToolVersions` 的 theia 欄位）一律標 `#[serde(default)]`**，
     v1 檔以 `report` 子命令仍可重建（全 repo 無讀取端檢查 `schema_version`，僅靠 default 相容）。
   - 讀取端新增：`schema_version` **大於** `SCHEMA_VERSION` 時以 i18n 鍵發出警告
     （舊版 binary 讀 v2 會靜默丟棄 crypto，此警告是唯一提示）。
   - golden baseline：新欄位在「未執行」情境下的序列化形態需釘死（`skip_serializing_if` 與否會改變 golden）。
8. **信任邊界（NFR-09）**：**約束範圍含 `ScanResult`、報表 HTML、日誌，以及原樣落地並可經
   `/api/v1/jobs/{id}/artifacts/cbom` 下載的 `cbom.cdx.json`**（`crates/cytrace-server/src/router.rs:52`）。
   只可記錄私鑰「存在、型別、長度、指紋、路徑」，**絕不含金鑰內容**；以含假私鑰 fixture 的測試斷言把關。
   - **退路（供應鏈審查第 5 項若實測發現 theia 輸出含金鑰內容）**：決策 5 的「不改寫」讓位於 NFR-09——
     依序採用：(a) 落地前遮蔽該欄位並在檔內註明已遮蔽；(b) 若無法安全遮蔽則不落地 `cbom.cdx.json`、
     僅保留 `ScanResult` 摘要。兩者皆須在報表 Notes 明示。
9. **可選閘門**：`--fail-on-quantum-vulnerable`（exit code 2，沿用 `failon.rs` 模式），預設不啟用。
   - **fail-closed**：指定本旗標時，若 CBOM 因引擎缺席 / 失敗 / 未請求而**未取得結果**，
     一律 **exit 1（錯誤）並說明原因**，不得回 0——「沒掃到」絕不等於「通過」。
   - `Unknown` 視為**未通過**（exit 2）；理由：軍規場域寧可誤報不可漏報。
   - CVE 閘門與量子閘門共用 exit 2 時，**輸出須指明是哪一個觸發**（CI 需可區分）。

## 修訂提議（人類已裁定：**接受三引擎**，2026-09-22）

> **裁定來歷**：2026-09-22，使用者於對話中經 AskUserQuestion 明示選擇「接受三引擎」
> （選項另有「否決，改自建 Rust 掃描」與「整份退回」）。本裁定為人類授權，非 AI 自行決定。
> **此裁定不等同 ADR 升 `Accepted`**——狀態仍為 `Draft`，升級須另經 `/asp:approve-adr`。

引入第三引擎與**已 Accepted 的治理文字正面衝突**。本節只**列出**待改清單，
**不在本分支修改任何一份**；待 ADR-013 升 `Accepted` 後由 ROADMAP **T908** 處理
（比照 ADR-011 對 NFR-09 的作法、T809 先例）。

| 文件 | 現行文字 | 衝突點 |
|------|----------|--------|
| `CLAUDE.md`（供應鏈純淨鐵則） | 「交件僅含 Syft/Grype（Apache-2.0）」 | 新增第三引擎 theia |
| `docs/SRS.md` NFR-05 | 「僅 Apache-2.0 第三方（Syft/Grype）」 | 同上；且 theia 內嵌 gitleaks 規則庫為 **MIT** |
| `docs/SRS.md` NFR-03 | 報表標註工具版本 | `ToolVersions` 需新增 theia 欄位（`#[serde(default)]`） |
| `README.md`、`docs/DELIVERY_SOP.md`（bin 清單 / NOTICE「皆 Apache-2.0」） | 兩引擎清單 | 需更新為三引擎並標註 MIT 成分 |
| `docs/adr/ADR-002` 成功指標 | 「全為 Apache-2.0」 | 依實況修訂 |

**已裁定「接受」** → 上表列為 ADR 升 `Accepted` 後的後續任務（ROADMAP T908），本 ADR 據以續行。
（「否決」情境已不適用：原將改走選項 B 或整份退回。）

## 供應鏈審查（核准前必須完成；實測見 ROADMAP T901b，須人類授權隔離環境）

本專案鐵則禁止中國來源依賴。theia 依賴樹需逐模組審查原產地與授權，審查結果附於本節：

| 項目 | 狀態 |
|------|------|
| `go list -m all` 全清單 + 授權彙整 | ⏳ 待做 |
| 間接依賴 `huandu/xstrings`（經 Masterminds/sprig）原產地判定 | ⏳ 待做（若不合規 → fork 剔除 sprig 或改選項 B） |
| 內嵌 gitleaks 規則庫授權（MIT）確認 | ⏳ 待做 |
| `GOOS=windows` 建置 + `dir` **與 `image`（docker-save tar）** 兩模式實測（ADR-010） | ⏳ 待做 |
| 假私鑰 fixture：確認 theia 輸出不含金鑰內容（決策 8；不合格則走退路） | ⏳ 待做 |
| theia 是否把 log 寫入 stdout 污染 JSON（決定是否需分流 stderr） | ⏳ 待做 |
| `--network none` 下實測離線性（目前僅為讀原始碼推論） | ⏳ 待做 |
| 釘選 syft 1.45.1 / grype 0.114.0 是否已含 `huandu/xstrings`（若是，裁定須三引擎一致） | ⏳ 待做 |

## 後果（Consequences）

**正面影響：**
- 交件新增 CBOM，可回應後量子遷移盤點需求；沿用既有單檔報表與離線交付鏈。
- 引擎選自中立基金會（PQCA / LF），本體與 Syft/Grype 同為 Apache-2.0。

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
| 私鑰不外洩 | 報表 / ScanResult / 日誌 / **落地的 `cbom.cdx.json`** 皆不含 fixture 金鑰內容 | 單元測試斷言 | 每次 CI |
| v1 相容 | v1 ScanResult 以 `report` 可重建 | 回歸測試 | 每次 CI |
| golden 穩定 | CBOM fixture golden 不變 | `tests/golden` | 每次 CI |
| 降級不影響主流程 | theia 缺席 / 執行失敗兩情境下，SBOM/CVE 報表正常、exit code 不變 | 整合測試（T907） | 每次 CI |
| 閘門 fail-closed | 指定 `--fail-on-quantum-vulnerable` 而未取得 CBOM 結果 → exit 1（非 0） | 整合測試（T907） | 每次 CI |
| 版本可稽核（NFR-03） | 報表標示 theia 版本 | 報表欄位檢查 | 每次 CI |
| CycloneDX 合規 | `cbom.cdx.json` 通過 vendored 1.6 schema 驗證 | 離線 schema 驗證 | 每次 CI |

## 關聯（Relations）

- **修訂（核准後必須同步改，否則文件互相矛盾）**：
  - ADR-009（ScanResult schema v2）
  - **SRS NFR-05**（`docs/SRS.md:63`「僅 Apache-2.0 第三方（Syft/Grype）」→ 納入 theia；
    並註記其內嵌 gitleaks 規則為 MIT，非全數 Apache-2.0）
  - **SRS NFR-03**（`docs/SRS.md:61` 工具版本標註 → `ToolVersions` 新增 theia 欄位，標 `#[serde(default)]`）
  - **CLAUDE.md 供應鏈鐵則**（「交件僅含 Syft/Grype（Apache-2.0）」→ 三引擎）
  - **ADR-002 成功指標**（「全為 Apache-2.0」→ 依 gitleaks MIT 實況修訂）
- 沿用：ADR-002（引擎選型原則、禁中國來源）、ADR-005（單檔報表）、ADR-007 / ADR-010 / ADR-012（交付鏈、雙平台、容器）、ADR-004（i18n）
- 參考：ROADMAP M9（T901 / T901b / T902–T907）
- 證據：`.asp-gate-log/20260922T075351Z-factcheck-ADR-013.md`（外部事實查證凍結快照）、
  `.asp-gate-log/20260922T075351Z-review-ADR-013.md`（獨立複審 NEEDS_WORK + 流程偏差揭露，錨點 `acb0142`）
