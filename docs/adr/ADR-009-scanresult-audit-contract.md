# [ADR-009]: ScanResult 稽核產物 schema 與報表重現契約

| 欄位 | 內容 |
|------|------|
| **狀態** | `Accepted` |
| **接受日期** | 2026-06-24（使用者授權代為升版） |
| **日期** | 2026-06-24 |
| **決策者** | CyTrace Team |

> **狀態說明：** `Draft`（初稿，禁止實作）→ `FIRM`（POC 驗證，允許 commit，需附驗證證據）→ `Accepted`（人類審核通過）

---

## 背景（Context）

CyTrace 的核心稽核能力是 `cytrace report <json>`：由先前產出的 **ScanResult JSON** **離線重現**同一份報表，供查核/複核
（原設計文件 §8 風險表「保留 report 重現機制供複核」）。這定義了 **core ↔ report 之間的穩定資料契約**，也是稽核人員從留存證據獨立重現報表的依據。
此外，報表是把 ScanResult 注入內嵌樣板產生的——**注入契約**若不定義，前端 bundle 與 Rust 注入器會各做各的、互不相容（T303 高複雜度任務的卡點）。
目前 ScanResult 結構只在 SDS §4 描述、注入只在 SDS §7 以「注入點（佔位）」帶過，**無 ADR 擁有 schema 穩定性與重現/注入契約**。

## 評估選項（Options Considered）

### 選項 A：版本化 ScanResult schema + 明定資料注入契約（sentinel + JSON script tag + 跳脫規則）
- **優點**：留存的 ScanResult 可跨 CyTrace 版本重現報表；前端與 Rust 注入器對同一契約實作；可稽核、可回溯。
- **缺點**：需維護 `schema_version` 與相容政策。
- **風險**：注入未正確跳脫會造成 HTML/script 破壞或 XSS 等價問題 → 以契約 + golden 測試（ADR-008）緩解。

### 選項 B：不版本化、注入細節留給實作
- **優點**：短期省事。
- **缺點**：舊證據無法保證可重現；前端/注入器契約不一致；軍方無法獨立複核。
- **風險**：稽核賣點落空。

## 決策（Decision）

採用 **選項 A**。

1. **schema 穩定性**：`ScanResult` 加 `schema_version` 欄位；定義向後相容政策——新版 `cytrace report` 須能重現舊版 ScanResult JSON。
2. **資料注入契約**（取代 SDS §7「注入點（佔位）」）：
   - 注入點＝樣板 head 內單一 sentinel：`<!--CYTRACE_DATA-->`。
   - 產生時替換為：`<script id="cytrace-data" type="application/json">{…}</script>`（`type=application/json` 使資料不進 `script-src`、避開多數跳脫陷阱）。
   - 前端以 `JSON.parse(document.getElementById('cytrace-data').textContent)` 讀取。
   - Rust 注入器**必須跳脫**：至少 `</` → `<\/`，加 U+2028/U+2029（若不用 script-tag 形式則另需處理裸 `<`）。
3. **重現契約**：`cytrace report <ScanResult.json>` 為純函式——同一 JSON（除 `meta.generated_at` 等時間欄位外）產生內容一致的報表。
4. **與 golden baseline 一致**：時間/易變欄位於比對前正規化或排除（見 ADR-008、SDS §9）。

## 後果（Consequences）

**正面影響：**
- 稽核人員可由留存 JSON 獨立重現報表；前端與注入器契約一致；注入安全（避免破版/XSS 等價）。

**負面影響 / 技術債：**
- 維護 schema 版本與相容性；注入器需完整跳脫實作與測試。

**後續追蹤：**
- SDS §4 加 `schema_version`；SDS §7 改寫為本注入契約；ROADMAP T303 description 引用本契約；FR-003 / SRS CLI 表交叉引用。

## 成功指標（Success Metrics）

| 指標 | 目標值 | 驗證方式 | 檢查時間 |
|------|--------|----------|----------|
| 舊 ScanResult 可被新版重現 | 是 | 以舊 JSON + 新 `cytrace report` 重現並比對（排除時間欄位） | M3/M5 |
| 注入跳脫安全 | 是 | golden 測試：欄位含 `</script>` 與 U+2028 仍正確 round-trip | M3 |
| 報表重現為純函式 | 是 | 同 JSON 兩次產出內容一致（排除 generated_at） | M3 |

## 關聯（Relations）

- 參考：ADR-005（單檔報表）、ADR-008（golden baseline 欄位正規化）、SDS §4/§7/§9、SRS FR-003/FR-006、ROADMAP T303

## 修訂：schema v2（2026-09-29，隨 ADR-013 / M9）

T903 宣稱「修訂 ADR-009」但當時只動了程式，本節補上契約文件（release 準備複審
major #25：稽核契約停在 v1 而程式已 v2，稽核者拿本檔對 JSON 會誤判欄位缺漏）。

- `schema_version`: **1 → 2**。
- 新增頂層欄位 `crypto`（`Option<CryptoInventory>`，`#[serde(default)]`）：
  `status`（`NotRequested` / `EngineAbsent` / `Completed` / `{ Failed: { reason_key,
  reason_detail? } }`，externally-tagged；`reason_key` 為純 i18n 鍵、`reason_detail`
  為不可翻譯細節）、`assets[]`（`name` / `asset_type` / `quantum` / `weak_key` /
  `location` / `primitive?` / `key_size?` / `not_after?`；**不含金鑰內容**，NFR-09）、
  三個未掃描計數（`unscanned_unreadable` / `unscanned_oversize` /
  `unscanned_undetermined`）。
- `meta.tool_versions` 新增 `theia?`（僅 CBOM 完成時填）；`meta` 新增
  `scan_identity?`（執行 uid，ADR-013 決策 10）。
- `meta.db_snapshot` 語意收緊：自本版起為 **grype db status 的真值**
  （`schemaVersion` / `built`）；取不到時為 sentinel `"unavailable"`（顯性失敗，
  不得假值）。v1 時期的 `"snapshot"` / `"unknown"` 為硬編碼假值，不具稽核效力。
- **向後相容政策不變**：v2 的 `cytrace report` 讀 v1 JSON 須可重建
  （`crypto` 缺欄位 → `None`；由回歸測試釘住）。
- 序列化形狀由 `cbom_status_serialization_matches_the_frontend_contract`
  （`crates/cytrace-types`）與跨語言契約測試（`crates/cytrace-i18n/tests/cbom_keys.rs`）
  機械釘住。

## 修訂：報表開啟語言（2026-10-05，T918）

**裁定來源**：使用者於 2026-10-05 同意「報表以產生時的語言開啟」（先前一律以 zh-TW 開啟）。
本修訂不動 ScanResult schema（仍為 v2），只調整決策 2 的注入點數量與決策 3 的重現輸入。

- **決策 2（注入契約）**：除資料 sentinel 外，新增第二個替換點：樣板根元素 `<html lang="zh-TW">`
  （必須恰好一個，否則產生報表即失敗）換成產生語言。前端 i18n 以它決定開啟時的語言，只接受
  zh-TW／en-US，其餘 → zh-TW。**先替換根元素、後注入資料**：資料內容（例如上傳目標的元件名）
  含同樣字串時，不影響計數與替換（由 cytrace-report 的回歸測試釘住）。
- **決策 3（重現契約）**：重現的輸入由「ScanResult JSON」改為「ScanResult JSON ＋ 語言」。
  - CLI：語言即 `--lang`／`CYTRACE_LANG`（皆無則 zh-TW）。
  - server：語言為送出掃描那次請求的語系；不落在 ScanResult 與 job 記錄裡，但**寫在報表本身**
    （`<html lang>`）。稽核者以 `cytrace --lang <該值> report <scan-result.json>` 即可重現同一份報表。
  - 語言只影響根元素的 `lang` 屬性；資料區塊與其餘內容不變。不同語言產出的兩份報表，排除
    `<html lang>` 後內容一致。
- **成功指標「報表重現為純函式」**：改為「同 JSON、同語言兩次產出內容一致（排除 generated_at）」。
- **不把語言寫進 ScanResult 的理由**：語言是呈現選擇，不是掃描結果；寫進去會讓同一次掃描因
  呈現語言不同而產生兩份不同的稽核資料，並觸發 schema 升版。

## 修訂：schema v3——來源標記（2026-10-07，T925）

**裁定來源**：使用者於 2026-10-07 核准實作計畫「報表來源標記」。範圍有三項：
- 逐筆元件的位置與 purl
- 弱點對應到元件的版本與位置
- 各區段標明產生資料的工具與版本

一個元件有多個位置時，報表精簡顯示，JSON 保留全部。

起因：報表只在封面列出工具版本。軟體產品文件表看不出元件來自哪個檔案。弱點的 `source`
是 Grype 的漏洞公告網址，不是元件位置，弱點也沒有元件版本。這些資料 Syft 與 Grype 的原始輸出都有，
只是解析時被丟掉。

- `schema_version`: **2 → 3**。新欄位一律 `#[serde(default)]`，空值不輸出。
- `Component` 新增三個欄位：
  - `bom_ref?`：CycloneDX `bom-ref`
  - `purl?`
  - `locations[]`：Syft 的 `syft:location:N:path` 依 N 排序，路徑相對於掃描根目錄
- `Vulnerability` 新增三個欄位：
  - `component_version?`
  - `component_purl?`
  - `locations[]`

  `component` 仍為元件名稱，語意不變。
- **弱點 → 元件位置的對應**採退路鏈，依序取第一個有結果的：
  1. Grype `artifact.locations`
  2. `artifact.id` 等於某元件的 `bom_ref`。命中即停：該元件沒有位置時留空，不退到 purl 聯集
     （否則會把同 purl 其他實例的位置掛到這筆弱點上）
  3. 同 `purl` 的所有元件位置聯集（比對前兩側先做 percent-decode：Syft 把 scoped npm 套件寫成 `%40babel`，
     Grype 重新序列化時可能寫成 `@babel`）。artifact 帶有 purl 時以此為準，對不到也不往下退：同名同版的套件
     可能屬於別的生態系（例如 npm 與 PyPI 都有 lodash），混進來就是猜測
  4. artifact 沒有 purl 時，才以同「名稱＋版本」的所有元件位置聯集
  5. 都對不到時留空，不猜測。

  Grype 自 SBOM 讀入時是否保留 id 與位置，在無漏洞 DB 的環境無法實測。若第 1、2 段都不成立，
  就由第 3 段接手：同 purl 出現在多處時取聯集（精準度較低）；purl 字串若有 percent-decode 之外的差異
  （例如 qualifiers 順序、大小寫），位置會留空（fail-closed，不猜測）。
  **實測結論（2026-10-07，T926）**：以釘選版 Syft 1.45.1、Grype 0.114.0 與漏洞 DB v6.1.10，對同一套件分布在兩份
  lockfile 的目錄實測，結果如下：
  - `artifact.id` 一律等於 CycloneDX 的 `bom-ref`（5／5）。
  - `artifact.locations` 逐實例保留：兩份 lockfile 的 lodash 各自帶自己的位置。
  - scoped npm 套件的 purl 在兩邊都是 `%40babel`，編碼一致。
  因此第 1 段（Grype 自帶位置）就是真實資料的主路徑，而且精準到實例；第 2 至 4 段只是防線。
  以真的 `cytrace run` 掃同一目錄，17 筆弱點全部帶有正確的位置。
- **Syft 的 `file` 類元件不進 ScanResult**（2026-10-07，T928；裁定來源：使用者 2026-10-07 選擇「排除」）：
  - 起因：Syft 把讀過的檔案（lockfile、執行檔等）列成 `type:"file"` 元件，以路徑為名，沒有版本、沒有 purl，
    不參與弱點比對。名稱的形態依目標而異（釘選 Syft 1.45.1 實測）：
    - `dir:` 與單檔目標：**主機絕對路徑**。Web 上傳解開後以 `dir:` 掃描，會露出 `<資料目錄>/jobs/<id>/input/extracted/…`；
      掛載則露出掃描根的主機路徑。
    - 壓縮檔目標：Syft 的暫存解壓路徑（`/tmp/syft-archive-contents-*/…`）。
    - 映像目標：映像內路徑（`/bin/busybox`），不是主機路徑。但它們同樣不是套件，alpine 映像的 96 列中有 79 列是這種元件。
  - 決定：`parse_cyclonedx` 略過 `type == "file"` 的元件，ScanResult 的 `components`、報表的軟體產品文件表、
    風險總評的元件總數都不含它們。其他類型照收，包含 `library`、`application`（執行檔，帶 purl、Grype 會比對 CVE）、
    `operating-system`。
  - 原始 `sbom.cdx.json` 與 `sbom.spdx.json` 是 Syft 的原樣輸出，不經本條過濾。
    （2026-10-08 起 Syft 以 `SYFT_FILE_METADATA_SELECTION=none` 執行，原始產物也不再含 file 元件，見「修訂：Web 模式不外露伺服器主機路徑」。）
  - schema 欄位不變，不升版。T928 之前產生的 JSON 若含 file 元件，`cytrace report` 重建時照原樣呈現，不改寫既有檔案。
  - 由三層測試釘住：
    - 單元測試：file 排除，library、application、operating-system 保留。
    - 共用 fixture 含一筆 file 元件，golden 快照因此不變；server 測試斷言 job 目錄的 `sbom.cdx.json` 與引擎輸出一字不差、
      `scan-result.json` 與 `/result` 不含 file 元件。
    - 真引擎測試：先斷言 Syft 原始輸出確實含 file 元件，再斷言解析結果一個都不留。
  - **當時尚未收掉的同類外露**（另案 #53，ROADMAP T931，擋 v0.6.0 發布；使用者 2026-10-07 裁定）。
    已由「修訂：Web 模式不外露伺服器主機路徑」處理：
    - `meta.target`（報表封面「受測目標」）仍是內部掃描目標字串，帶資料目錄或掃描根的主機路徑。
    - CBOM 失敗的 `reason_detail` 帶目標路徑。
    - Web 模式可下載的原始產物（`sbom.cdx.json`、`sbom.spdx.json`、`grype.json`）帶同樣的主機路徑，出現在來源描述，
      以及 `dir:`／單檔目標的 file 元件名稱。原始產物不經本條過濾。使用者 2026-10-07 裁定併入 #53 一起處理。
- **區段來源**不新增欄位，報表由既有的 `meta.tool_versions` 與 `meta.db_snapshot` 組出。
- **信任邊界（NFR-09）**：位置是相對於掃描目標根目錄的路徑，與 CBOM 資產的 `location` 同性質。
  只記路徑，不含檔案內容。
- **向後相容政策不變**：v3 的 `cytrace report` 讀 v1、v2 JSON 須可重建。新欄位缺漏時視為空，
  報表的軟體產品文件表位置欄以「—」呈現，弱點列不顯示位置行。由回歸測試釘住。
- 讀到 v3 JSON 的舊版 CyTrace（v2）會略過未知欄位並警告 `cli.schema_ahead`；這是既有機制，行為不變。

## 修訂：Web 模式不外露伺服器主機路徑（2026-10-08，T931／#53）

**裁定來源**：使用者於 2026-10-08 逐點裁定下方提案 1、3、5、6，四點皆採提案內容；提案 2、4、7 為提案 1 的直接推論。

**起因**：T928 複審揭露，Web 模式交出去的產物仍帶伺服器的主機路徑：
- 上傳時帶資料目錄，例如 `<資料目錄>/jobs/<id>/input/…`。
- 掛載時帶掃描根。

這不符 NFR-09「報表只含依賴與弱點中繼資料、掃描目標不離開場域」。實測各產物的外露點如下（2026-10-07）：

| 產物 | 外露位置 |
|---|---|
| ScanResult／報表封面「受測目標」 | `meta.target` 寫入的是交給引擎的內部字串（`runner.rs`） |
| ScanResult／報表 CBOM 區 | 失敗時 `reason_detail` 帶目標路徑（`engine::cbom_target`） |
| `sbom.cdx.json` | 來源描述 `metadata.component.name`；`dir:` 與單檔目標的 file 元件名稱 |
| `sbom.spdx.json` | `name`、`documentNamespace`、根套件名稱 |
| `grype.json` | `source.target`（取自 SBOM 的來源描述）；`descriptor` 內的漏洞 DB 路徑 |
| `cbom.cdx.json` | 無。theia 的資產位置本來就是相對路徑（實測含憑證的目錄） |

**引擎參數實測**（釘選 Syft 1.45.1、Grype 0.114.0，真實漏洞 DB）：`--source-name`、`--base-path` 與 Grype `--name` 實測四種目標
（目錄、映像 tar、單檔執行檔、原始碼 tar；扁平 OCI 由真實端到端涵蓋），file 選擇設定實測五種目標（另加扁平 OCI）：
- Syft `--source-name <名稱>`：CycloneDX 與 SPDX 的來源描述不再含路徑。Grype 從 SBOM 讀來源描述，`source.target` 也跟著乾淨。元件數與弱點數不變。
- Syft `--base-path`：對 file 元件名稱沒有作用，不採用。Grype `--name` 亦無作用，不採用。
- 環境變數 `SYFT_FILE_METADATA_SELECTION=none`：Syft 不再輸出 file 元件，原始 CycloneDX 從此不含 file 元件的路徑。
  SPDX 的 `files` 段仍在，但檔名是相對於掃描目標的路徑（例如 `bin/busybox`、`requirements.txt`），不含主機路徑
  （2026-10-09 補記，v0.6.0 CHANGELOG 複審查出；伺服器端到端實測）。
  - 五種目標的套件清單、套件位置、弱點清單三組指紋前後完全相同，只少了 file 元件。
  - file 元件在 T928 已排除於 ScanResult 之外，報表不受影響。
- 兩者都是引擎原生設定，不事後改寫原始檔，原始產物仍是「引擎的原樣輸出」。
- 剩下的是 `grype.json` `descriptor` 內的漏洞 DB 路徑。它是伺服器的安裝位置，與掃描目標或 job 無關。

**決定**：
1. `meta.target`：Web 模式改寫 job 描述（`upload:<檔名>`、`mounted:<root>/<path>`，與 job API 的 `target` 相同）。CLI 模式不變，仍是使用者輸入的目標字串，那是使用者自己給的值。
2. Syft 呼叫加 `--source-name`：Web 模式用 job 描述。CLI 模式不加，維持 Syft 預設，也就是使用者給的目標，與現況相同。
   （草案原寫「CLI 用使用者輸入的目標字串」；實作時改為不加，因為 Syft 預設的來源名稱與目標字串略有差異，不加才真正「與現況相同」。）
3. Syft 呼叫加 `SYFT_FILE_METADATA_SELECTION=none`，CLI 與 Web 兩種模式都加，引擎呼叫只有一種形態。
   - **這會改變 T928 的一句話**：「原始 sbom.cdx.json 保留完整內容（含 file 元件）」改為「原始產物不含 file 元件」。
   - 套件、位置與弱點不變（實測）。
4. CBOM `reason_detail`：Web 模式以 job 描述取代目標路徑，`reason_key` 不變。
5. `grype.json` 的漏洞 DB 路徑：照原樣保留並寫明，不事後改寫原始檔。
6. 重建 v0.6.0 以前的 JSON：不在報表渲染端過濾。舊檔的 `meta.target` 本來就帶路徑，只過濾 file 元件也收不乾淨；若要交出乾淨的報表，請以 v0.6.0 重新掃描。
7. #51（失敗訊息加上 Syft 錯誤摘要）實作時，摘要不得重新帶回資料目錄或掃描根的路徑。本節的整合測試會擋住這件事。

**驗證分工**（依產物的來源分層；草案原寫「server 整合測試含四種可下載產物」，實作改為下列分工）：
- 單元測試：Syft 呼叫帶 `--source-name` 與 file 選擇設定。
- server 整合測試：CyTrace 自己寫出的內容（ScanResult、報表、job API、CBOM 失敗成因、引擎失敗細節）不含資料目錄與
  掃描根。反空轉：先斷言內部掃描目標確實含這些路徑。
  - 原始產物是引擎的原樣輸出，fake 引擎回傳的是固定 fixture，用它驗原始產物沒有意義，所以不在這一層。
- 真引擎測試：以來源名稱呼叫 Syft 後，原始 CycloneDX／SPDX 不含掃描根；CycloneDX 沒有 file 元件；套件與 Syft 預設呼叫相同。
  - `grype.json` 的 `source.target` 取自 SBOM 的來源描述（實測），CycloneDX 的來源描述已由此斷言。
    CI 的真引擎 job 沒有漏洞 DB，Grype 無法比對，所以 `grype.json` 沒有自動化回歸，由真實端到端與場域驗收承接。
- 真實端到端：上傳與掛載逐一掃描，逐檔搜尋主機路徑。

提案 3 改變了 T928 原先「原始 sbom.cdx.json 保留 file 元件」的說法，使用者已明確同意。

**實作**：
- `engine::syft_scan` 統一組 Syft 指令，一律帶 `SYFT_FILE_METADATA_SELECTION=none`。
- `ScanEngine::sbom_with_spdx_named` 帶 `--source-name`。預設實作忽略名稱，既有 fake 引擎不用改。
- server 的 runner 以 job 描述呼叫上述方法，並寫入 `meta.target`。
- `runner::redact` 把 CBOM `reason_detail` 與 job 錯誤細節中的內部目標換成 job 描述。目標的三種形態都會替換：原字串、去前綴的路徑、正規化後的絕對路徑。

**驗證**（2026-10-08）：
- 單元測試：Syft 指令的參數與環境變數；`redact` 替換三種形態；取不到 job 描述時以 `job:<id>` 代替，不得為空。
- server 整合測試：
  - 掛載與上傳兩條路徑，引擎收到的來源名稱都是 job 描述。
  - `meta.target` 是 job 描述。
  - ScanResult、報表、job API 都不含主機路徑；CBOM 失敗成因與引擎失敗細節亦同。
  - 每支都先斷言內部目標確實含主機路徑，防止測試空轉。
- 真引擎測試：以來源名稱呼叫時，原始 CycloneDX 與 SPDX 都不含掃描根；CycloneDX 沒有 file 元件；`sbom()`（CLI 路徑）同樣沒有 file 元件。
- SPDX 合規（2026-10-09，v0.6.0 發布前）：以 spdx-spec `support/2.3` 分支目前的 `schemas/spdx-schema.json`
  （sha256 `4126dc29…3212`；與 2026-10-05 所用版本不同，分支已更新）驗證三種目標的輸出，皆零違規：映像 tar、Go 執行檔、
  路徑含空白與中文的目錄。後者的 `documentNamespace` 由 Syft percent-encode，為合法 URI（#55）。
- 突變測試：T931 自身的 10 個突變全部轉紅（另有 1 個驗 T928 的 server 測試改寫後仍有效），涵蓋關掉 file 選擇、不帶來源名稱、`meta.target` 用內部目標、不做遮蔽、遮蔽漏掉正規化路徑、
  named 路徑套件與預設不同、取不到 job 描述時退回空字串等情形。
- 真實端到端：釘選三引擎、真實 DB、帶 CBOM，涵蓋上傳 zip／tar／tar.gz，以及掛載目錄、映像 tar、原始碼 tar、執行檔、扁平 OCI、巢狀目錄，共 9 個 job。每個 job 都先確認搜尋用的路徑確實是它的
    資料目錄與掃描根（反空轉）。
  - 檢查範圍：ScanResult、報表、`sbom`／`spdx`／`grype`／`cbom` 四種原始產物、job API。
  - 主機路徑外露合計 0。
  - 元件、弱點、CBOM 數字與修正前相同。
