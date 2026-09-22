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
- 靜態建置（`CGO_ENABLED=0`）與離線性**已於 `v1.1.2@dcd95ac` 實建實測**（兩次不同路徑建置 SHA256 一致；
  建置與 `dir` / `image` 掃描全程 `--network none` 通過）——見下方「供應鏈審查」表與
  `.asp-gate-log/20260922T075351Z-factcheck-ADR-013.md`。
- ⚠ **外連行為的正確描述**：**並非「只有在給 registry 參照時才走網路」**。實測顯示
  **輸入不可讀時 theia 會自行回退嘗試 docker daemon / podman / containerd / registry**
  （見下方「新發現二」）——使用者未給 registry 參照也可能送出請求。
  故決策 2 的輸入限制**與 image 前置可讀性檢查**同為零外連（NFR-01）的必要防線。
- **殘餘未驗**：Windows 平台實跑、OCI layout 目錄模式（見快照「尚未查證」節）。
- 偵測：X.509 憑證（簽章/公鑰演算法）、公私鑰與密鑰（內嵌 gitleaks 規則）、`openssl.cnf`（TLS 版本/cipher suite）、
  `java.security`（disabledAlgorithms 信心值）。輸出 CycloneDX **1.6 JSON**（stdout）。
- **缺點**：依賴樹大（vendor 153 模組）；不掃原始碼；Windows **僅驗交叉編譯產出格式（PE32+），平台實跑未驗**；
  失敗路徑有隱含外連回退（見上）。

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
   - **釘死的是 vendored 原始碼 tarball 的 SHA256 + `go.sum`**；binary SHA256 為建置產物紀錄，隨交付附上。
   - **建置地點單一化**（避免三處各建產生不同 SHA）：theia binary **只由 Dockerfile 的 go builder stage
     （或 CI 的等價步驟）建置一次**，產物與其 SHA256 作為釋出資產；`package.sh` / `package.ps1`
     **沿用現行模式取用該產物**，不各自重建。
     注意現況：`scripts/package.sh` 由 PATH 複製引擎、`scripts/package.ps1` 自 GitHub releases 下載——
     而本決策明文「不依賴上游 release binary」，故 **Windows 交付鏈需改為取用我方建置的產物**（併入 T902）。
   - Go builder base image **須以 digest 釘選**，比照 Dockerfile 既有三個 `FROM ... @sha256` 慣例。
2. **輸入限制**：**限制實作於 `engine::cbom` 自由函式層**（非僅 `RealEngine`——CLI 走
   `engine::sbom` / `engine::vuln` 自由函式，不經 `RealEngine`，見 `crates/cytrace-cli/src/main.rs:126`）：
   只允許 `dir <本地路徑>` 與 `image <docker-save tar / OCI layout>`，**拒絕 registry 參照**（防止觸發外連）。
   **目標字串轉譯規則**：CyTrace 目標語法沿用 syft（`dir:`、`docker-archive:`、單檔路徑、裸映像名）；
   轉譯時 —— 既有目錄 → `dir`；既有 tar / OCI layout 目錄 → `image`；
   **裸映像名或任何無法在本地判定的形態 → 拒絕（回報 i18n 錯誤鍵，不猜測）**。
   **可讀性前置條件（兩模式皆適用）**：轉譯**不得只做存在性判定**——目標必須**實際開檔成功**才轉譯，
   不可讀即拒絕並回 i18n 錯誤鍵，**不得 spawn theia**。理由：存在但不可讀的 tar 會被 theia 當成
   「本地取得失敗」而回退嘗試 registry（見「新發現二」），屆時請求已送出，事後偵測來不及。
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
   - **決策 10 所需的兩個欄位一併入契約**（否則報表顯示不出來，且 `report` 子命令無法從存檔重建）：
     `CryptoInventory.unscanned_count`（因權限未掃描的項目數）與 `Meta.scan_identity`（執行身分）。
     `Meta` 為 ADR-009 凍結的封閉 struct（`crates/cytrace-types/src/lib.rs:102-107`），
     新增欄位只能經本決策這個修訂出口；兩者皆標 `#[serde(default)]`，
     並把「未執行」情境下的序列化形態納入 golden 釘死。
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
   - **批次語意（必須明訂，否則 fail-closed 會被吞掉）**：現行 `batch` 的彙整只認 `EXIT_FAILON`
     （`crates/cytrace-cli/src/main.rs:143-149`：`worst` 初值 `EXIT_OK`，僅 `== EXIT_FAILON` 會抬高），
     而決策 4 已把「引擎缺席」改為 `Ok(None)`、不再有錯誤物件可由 `?` 傳播 ——
     **照現行文字實作，`batch --cbom --fail-on-quantum-vulnerable` 在引擎缺席時會回 0**，
     正是本決策要防的情境。故明訂退出碼優先序：**任一目標 exit 1 → 整批 1（優先於 2）；
     否則任一目標 exit 2 → 整批 2**；`run_one` 的彙整條件須一併修改，不可只比對 `EXIT_FAILON`。
   - 成功指標的 fail-closed 驗證**須涵蓋 `run` 與 `batch` 兩者**。
10. **執行環境硬性條件（T901b 實測後新增）**：
    - **必須提供可寫 `HOME`**：`HOME` 不可寫時 theia 會把非 JSON 訊息印到 **stdout** 汙染輸出。
      `engine::cbom` 一律以 `HOME=<專用暫存目錄>` 啟動；且**解析前先驗證 stdout 為合法 JSON**，
      失敗即歸為 `CbomStatus::Failed`（決策 4），不得把污染後的內容當結果。
    - **空輸出不得視為「無密碼資產」**：實測顯示輸入不可讀時 theia 會 **stdout 空白 + exit 0**
      （並回退嘗試 registry）。故 `engine::cbom` 遇**空輸出或非 JSON** 一律歸 `CbomStatus::Failed`，
      **絕不映射為「掃到 0 項」**。
    - **可讀性前檢：兩模式皆適用**（image 不可讀會觸發 registry 回退，見新發現二）。
      **靜默漏檢**則僅 `dir` 模式會發生——實測顯示權限不足時 theia 完全未回報 `0600` 私鑰、
      無警告、exit 0；`image`（tar）模式讀 layer 內容，不受宿主權限影響。故：
      - CLI 模式以呼叫者身分執行，**掃描前檢查目標可讀性**，遇不可讀項目須計數並在報表顯性標示
        「因權限未掃描 N 項」——**不得無聲略過**；
      - 容器 / server 模式（distroless nonroot 65532）同理；沿用 `f98e021` 對 image SBOM 的處置慣例，
        必要時以指定 UID 執行，並把採用的身分寫入報表 meta。
    - 成功指標新增對應測試（見下）。

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

**實測環境**（2026-09-22 執行，ROADMAP T901b）：拋棄式 `golang:1.26.1` 容器，原始碼為
`git clone --branch v1.1.2` → commit `dcd95ac86d1cbe6e867ff3ee059b9ef77bac6a59`，clone 置於 repo 外暫存區；
**抓取階段**（`go mod vendor`）開網路，**建置與執行階段一律 `--network none`**，不掛家目錄、不掛 docker.sock。

| 項目 | 狀態 |
|------|------|
| 依賴清單 + 授權彙整 | ✅ vendor **153 模組**，其中 **134 個模組帶自己的 LICENSE 檔**（差額 19 為同一 repo 下共用上層授權的子模組，例如 `golang.org/x/*`、`go.opentelemetry.io/*` 家族）；深度掃描共 **122 份授權檔**（含子目錄內的附屬授權）。類型：Apache 42、MIT 42（另 7 份為未標題的 MIT 全文）、BSD 4、ISC 1、**MPL-2.0 3**。**無 GPL / AGPL / LGPL**（判定指令：`grep -rlniE "GNU (GENERAL\|AFFERO\|LESSER) PUBLIC LICENSE" vendor --include="LICENSE*"` → 僅 3 筆命中，逐一開檔確認皆為 **MPL-2.0 相容性條款**中提及 GNU 之字樣，非 GPL 授權） |
| MPL-2.0 三項 | ✅ `hashicorp/golang-lru`、`hashicorp/go-version`、`cyphar/filepath-securejoin`。檔案級弱 copyleft，靜態連結散布可接受，**須列入 NOTICE**（掛 T902，見下） |
| **全量原產地盤點（153 模組）** | ✅ 已做。**域名層**：`github.com` 132、`golang.org` 6、`go.opentelemetry.io` 5、`google.golang.org` 3、其餘 7 個各 1；**無 `.cn`、無 gitee，無任何中國企業網域**。**著作權層**：對全 vendor 的 LICENSE 與 `.go` 檔掃描中國企業／城市關鍵字（alibaba/aliyun/tencent/baidu/huawei/bytedance/xiaomi/pingcap/qiniu/didi/beijing/shanghai/shenzhen/hangzhou/china 等）→ **零命中**。**組織層**：72 個 GitHub 擁有者逐一檢視，**無任何中國企業或中國開源組織**（無 OpenSCA 類專案） |
| 個人維護者國籍 | ⚠ **方法上無法機械判定，亦未判定**。已知具個人身分線索者：`huandu/xstrings`（`Copyright (c) 2015 Huan Du`）、`STARRY-S/zip`（`Copyright (c) 2023, Starry`）。**裁定建議**：CLAUDE.md 鐵則的規範對象是**中國來源的專案／組織**（原文舉例為 OpenSCA-cli），個人貢獻者國籍既不可驗證亦非該鐵則本意；若要改採「個人亦納管」，須先修鐵則並**同步適用於現行 syft/grype**（見下列） |
| `huandu/xstrings` 是否為 theia 獨有 | ✅ **否**：釘選的 **syft v1.45.1 與 grype v0.114.0 的 `go.sum` 同樣含 `huandu/xstrings v1.5.0`（經 `Masterminds/sprig v3.3.0`）**——現行交件早已包含，非 theia 增量。是否排除須三引擎一致裁定 |
| 內嵌 gitleaks 規則庫授權 | ✅ `zricethezav/gitleaks/v8 v8.30.1` **MIT**、`gitleaks/go-gitdiff v0.9.1` **MIT** |
| `GOOS=windows` 建置（ADR-010） | ✅ 交叉編譯成功，產物為 PE32+ x86-64 console executable |
| 可重現建置 | ✅ 以決策 1 的參數於**兩個不同路徑**各建一次，SHA256 相同：`672a3d06ce32d1a242f0f4c10dc0280c257fa4717ecf9c7c6e5f2718bf3adecf`（linux/amd64，27,947,134 bytes，`statically linked, stripped`） |
| 假私鑰 fixture：輸出不含金鑰內容（決策 8） | ✅ **通過**。RSA-2048 / RSA-1024 / Ed25519 私鑰與一組隨機假 AWS 憑證皆被偵測，輸出只含型別、長度、格式（PEM）、OID 與檔案路徑；三個私鑰檔的任一 40 字元片段、access key id 與 secret 值**皆未出現在輸出中**；`PRIVATE KEY` 標記 0 命中。→ 決策 5「原樣落地」與 NFR-09 **不衝突**，退路暫不需啟用 |
| theia 是否污染 stdout | ⚠ **會**。`HOME` 不可寫時，`could not create application folder …` 會印到 **stdout**，使 JSON 解析失敗（exit code 仍為 0）。→ 見決策 10 |
| `--network none` 離線性 | ✅ 建置與 `dir` 掃描全程 `--network none` 成功；唯獨需可寫 `HOME` |
| `image`（docker-save tar）模式 | ✅ 通過。`docker save` tar 掃描成功（3,499–3,714 元件，含 base image CA 憑證庫）；**私鑰偵測不受宿主權限影響**——以 nonroot(65534) 與 root 掃同一 tar，結果完全相同（RSA-2048 / RSA-1024 / ED25519 皆偵測到，含 `size`）；輸出同樣不含金鑰內容 |
| 輸入不可讀時的行為（image 模式） | ⚠ **危險**：tar 不可讀時錯誤只寫 stderr、**stdout 空白、exit code 仍為 0**；且會**依序回退嘗試 docker daemon / podman / containerd / registry**，stderr 可見 `Get "https://index.docker.io/v2/"` —— **隱含外連**，見決策 2 與決策 10 |

### ⚠ 新發現一：`dir` 模式下權限不足會靜默漏檢

同一份 fixture，以**非 root（65534）**執行 `dir` 掃描時，三個 `0600 root:root` 的私鑰檔**完全未被偵測**，
只找到 `0644` 的那一個；**無錯誤、無警告，exit code 仍為 0**。
這與既有的 image SBOM 問題同類（見 commit `f98e021`：syft 需 `--user 0:0` 才掃得到 tar）。
對 CyTrace 影響重大——容器交付跑 distroless **nonroot（65532）**，掃描掛載目錄時會**靜默低報**私鑰。

**範圍界定（實測釐清）**：此問題**只存在於 `dir` 模式**。`image`（tar）模式讀的是 layer 內容，
不受宿主檔案權限影響，nonroot 與 root 結果一致。

### ⚠ 新發現二：`image` 模式輸入不可讀時會回退嘗試外連

tar 檔不可讀時，theia 依序嘗試 docker daemon → podman → containerd → **registry**，
stderr 出現 `failed to get image descriptor from registry: Get "https://index.docker.io/v2/"`。
在 `--network none` 下該嘗試失敗，但**在有網路的環境會真的送出請求**——違反零外連鐵則。
且此情境下 **stdout 空白、exit code 仍為 0**，呼叫端若只看 exit code 會誤判為「掃描成功、無密碼資產」。
→ 決策 2「拒絕 registry 參照」因此不只是防呆，而是**必要防線**；並見決策 10 的空輸出處置。

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
| 零外連（正常路徑） | `--network none` 下 `run --cbom` 成功 | 離線 E2E | 每次 release |
| 私鑰不外洩 | 報表 / ScanResult / 日誌 / **落地的 `cbom.cdx.json`** 皆不含 fixture 金鑰內容 | 單元測試斷言 | 每次 CI |
| v1 相容 | v1 ScanResult 以 `report` 可重建 | 回歸測試 | 每次 CI |
| golden 穩定 | CBOM fixture golden 不變 | `tests/golden` | 每次 CI |
| 降級不影響主流程 | theia 缺席 / 執行失敗兩情境下，SBOM/CVE 報表正常、exit code 不變 | 整合測試（T907） | 每次 CI |
| 閘門 fail-closed | 指定 `--fail-on-quantum-vulnerable` 而未取得 CBOM 結果 → exit 1（非 0）；**`run` 與 `batch` 皆須驗** | 整合測試（T907） | 每次 CI |
| 零外連（失敗路徑） | 以**不可讀 tar** 觸發：斷言 theia **未被 spawn**、stderr 無任何 registry 嘗試字串 | 整合測試（T907） | 每次 CI |
| 版本可稽核（NFR-03） | 報表標示 theia 版本 | 報表欄位檢查 | 每次 CI |
| CycloneDX 合規 | `cbom.cdx.json` 通過 vendored 1.6 schema 驗證 | 離線 schema 驗證 | 每次 CI |
| stdout 純淨 | theia 輸出非合法 JSON 時歸為 `Failed`，不得誤判為空結果 | 單元測試（餵污染輸出） | 每次 CI |
| 權限漏檢顯性化 | 目標含不可讀檔案時，報表顯示「因權限未掃描 N 項」 | 整合測試（`0600` fixture 以非 owner 身分掃） | 每次 CI |

## 關聯（Relations）

- **修訂（核准後必須同步改，否則文件互相矛盾）**：
  - ADR-009（ScanResult schema v2）
  - **SRS NFR-05**（`docs/SRS.md:63`「僅 Apache-2.0 第三方（Syft/Grype）」→ 納入 theia；
    並註記其內嵌 gitleaks 規則為 MIT，非全數 Apache-2.0）
  - **SRS NFR-03**（`docs/SRS.md:61` 工具版本標註 → `ToolVersions` 新增 theia 欄位，標 `#[serde(default)]`）
  - **CLAUDE.md 供應鏈鐵則**（「交件僅含 Syft/Grype（Apache-2.0）」→ 三引擎）
  - **ADR-002 成功指標**（「全為 Apache-2.0」→ 依 gitleaks MIT 實況修訂）
  - **ADR-007**（交付包裝）：`DELIVERY_SOP` 的 bin 清單目前只有 `cytrace` / `syft` / `grype`，須納入 theia；
    NOTICE 須加列 **MPL-2.0 三項**與 gitleaks MIT
    （落點：`scripts/package.sh:48-61`、`scripts/package.ps1:83-89`，掛 **T902**——NOTICE 產生器所在處）
  - **ADR-012**（容器化）：Dockerfile 需新增 go builder stage 建 theia，四階段結構與 base image digest 釘選規則同步
- 沿用：ADR-002（引擎選型原則、禁中國來源）、ADR-005（單檔報表）、ADR-010（雙平台）、ADR-004（i18n）、ADR-008（測試與 golden，套用既有規範）
- 關聯文件：SDS §3（子程序編排：Syft / Grype → 加入 theia）、SDS §4（`Meta` 結構新增 `scan_identity`）
- 參考：ROADMAP M9（T901 / T901b / T902–T907）
- 證據：`.asp-gate-log/20260922T075351Z-factcheck-ADR-013.md`（外部事實查證凍結快照）、
  `.asp-gate-log/20260922T075351Z-review-ADR-013.md`（獨立複審 NEEDS_WORK + 流程偏差揭露，錨點 `acb0142`）
