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
  - 起因：Syft 把讀過的檔案（lockfile、執行檔等）列成 `type:"file"` 元件，名稱是**主機絕對路徑**。
    Web 模式下會露出 `<資料目錄>/jobs/<id>/input/…`；這些元件沒有版本、沒有 purl、不參與弱點比對。
    T926／T927 的實測報表中，軟體產品文件表因此混入以路徑為名的列（alpine 映像 96 列中有 79 列是 file）。
  - 決定：`parse_cyclonedx` 略過 `type == "file"` 的元件，ScanResult 的 `components`、報表的軟體產品文件表、
    風險總評的元件總數都不含它們。其他類型照收，包含 `operating-system`。
  - 原始 `sbom.cdx.json` 與 `sbom.spdx.json` 是 Syft 的原樣輸出，**不受影響**，照常完整交付。
  - schema 欄位不變，不升版。T928 之前產生的 JSON 若含 file 元件，`cytrace report` 重建時照原樣呈現，不改寫既有檔案。
  - 由單元測試與真引擎測試釘住：真引擎測試先斷言 Syft 原始輸出確實含 file 元件，再斷言解析結果一個都不留。
  - **尚未收掉的同類外露**：Web 模式下 `meta.target`（報表封面「受測目標」）仍是內部掃描目標字串，帶資料目錄或
    掃描根的主機路徑；CBOM 失敗的 `reason_detail` 亦然。另案 #53（ROADMAP T931）處理，擋 v0.6.0 發布（使用者 2026-10-07 裁定）。
- **區段來源**不新增欄位，報表由既有的 `meta.tool_versions` 與 `meta.db_snapshot` 組出。
- **信任邊界（NFR-09）**：位置是相對於掃描目標根目錄的路徑，與 CBOM 資產的 `location` 同性質。
  只記路徑，不含檔案內容。
- **向後相容政策不變**：v3 的 `cytrace report` 讀 v1、v2 JSON 須可重建。新欄位缺漏時視為空，
  報表的軟體產品文件表位置欄以「—」呈現，弱點列不顯示位置行。由回歸測試釘住。
- 讀到 v3 JSON 的舊版 CyTrace（v2）會略過未知欄位並警告 `cli.schema_ahead`；這是既有機制，行為不變。
