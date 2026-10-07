# SDS — CyTrace 軟體設計規格書

| 欄位 | 內容 |
|------|------|
| **文件** | Software Design Specification |
| **專案** | CyTrace |
| **版本** | 0.4 |
| **日期** | 2026-10-05 |
| **狀態** | 現行，與 v0.5.0 程式碼對齊 |
| **對應** | SRS（FR-001…010、NFR-01…09）、ADR-001～013 |

> **v0.4 改寫（T910）**：本版取代 0.1 草案與 v0.3.0 的檔頭增補。原稿寫於只有 Syft／Grype 兩個引擎的時期，
> 現已對齊三引擎（加入 CBOM 引擎 cbomkit-theia，ADR-013）、`ScanResult` schema v3（ADR-009 修訂節）、
> Web 服務模式（ADR-011／012）與操作者終端 i18n（T912）。
> 本文描述**設計與契約**；細部行為以程式碼的文件註解為準，各節會指出位置。

---

## 1. 架構總覽

CyTrace 是 **Rust Cargo workspace 單體**：以子程序呼叫三個外部引擎，前端在建置期打包成單檔、
內嵌進 binary。入口有兩個：CLI 子命令，以及 `serve` 的 Web 服務模式。兩者共用同一條掃描管線。

```
 目標（目錄／docker-save tar／OCI layout／檔案系統）
        │
        ▼
 cytrace-cli ── run｜batch｜scan｜report｜serve｜hash-password｜health
        │                               │
        │ CLI 直接呼叫                   │ serve → cytrace-server（axum）
        │                               │   job 佇列 → spawn_blocking
        ▼                               ▼
 ┌──────────────── cytrace-core：掃描管線 ─────────────────┐
 │  engine::sbom   → syft  ──→ CycloneDX JSON（sbom.cdx.json）│
 │                         └─→ SPDX 2.3（sbom.spdx.json，選用）│
 │  engine::vuln   → grype ──→ grype JSON（離線 DB）          │
 │  engine::cbom   → cbomkit-theia ──→ CBOM（僅 --cbom 時）   │
 │        │                                                  │
 │  parse → 統一模型 → severity／風險總評 → quantum 判定       │
 │        → fail-on／量子閘門                                 │
 └───────────────────────────┬─────────────────────────────┘
                             ▼
                 ScanResult（schema v3，ADR-009）
                             ▼
 cytrace-report（內嵌單檔樣板 → 注入資料 → *.report.html）
```

- CBOM 分支**預設關閉**（ADR-013 決策 4）。開啟後若引擎缺席或失敗，只影響 `crypto` 區段，
  SBOM 與漏洞結果照常產出。
- 終端訊息與 API 回應的語言分屬兩套規則（§6、§10）。

**互動式元件總覽**：[`docs/architecture/cytrace-arch.html`](architecture/cytrace-arch.html)（離線單檔，用瀏覽器開啟）。
上圖是管線視角；那份圖另外畫出 Web 控制台、認證層、工作目錄與 volume、上傳型目標掃完即刪，
並標出場域邊界與單一 binary 邊界。各節點附原始碼連結，釘在 commit `59f0e92`。

- 圖由 archify 依 [`cytrace-arch.json`](architecture/cytrace-arch.json) 產生：
  `archify deliver architecture cytrace-arch.json cytrace-arch.html --quality showcase --repo-root <CyTrace checkout>`。
- 產生後須刪除 Google Fonts 的 `<link>`，以符合零外連。字型會改用系統 monospace。
  刪完以 `bash scripts/console-egress-check.sh docs/architecture` 自檢。
- 這張圖是文件快照，不由 CI 檢查。架構有變動時，改 JSON 後重新產生。

## 2. Workspace crate 切分

| crate | 職責 | 主要依賴 |
|-------|------|---------|
| `cytrace-types` | 共用領域型別，零業務邏輯：`Severity`、`Component`、`Vulnerability`、`Meta`、`ScanResult`、`CryptoInventory`、`CbomStatus`、`QuantumStatus` | serde |
| `cytrace-core` | 子程序編排（`engine`）、解析（`parse`）、嚴重度與風險總評（`severity`）、量子判定（`quantum`）、閘門（`failon`）、時間格式（`timefmt`）、錯誤分類（`error`） | cytrace-types、serde_json、thiserror |
| `cytrace-i18n` | 輕量 catalog（`Catalog`、`Localized`、`lang_code`），CLI 與 server 共用；locale 以 `include_str!` 內嵌 | serde_json |
| `cytrace-report` | 內嵌報表樣板、依注入契約產出單檔 HTML（§7） | cytrace-types、cytrace-core、cytrace-i18n |
| `cytrace-server` | Web 服務模式：axum 路由、認證、session、job 佇列與落盤、上傳解壓、掛載白名單、TLS、console 靜態檔（§10） | axum、axum-server、tokio、rustls（ring）、argon2、zip／tar／flate2、rust-embed |
| `cytrace-cli` | clap 子命令、語言解析、終端錯誤渲染、退出碼；feature `server`（預設開啟）納入 `serve`／`hash-password`／`health` | clap、anyhow、cytrace-server（optional） |

模組邊界：
- 解析、評級與閘門邏輯只住在 `cytrace-core`；型別只住在 `cytrace-types`；CLI 與 server 不含業務規則。
- 渲染 CBOM 錯誤的邏輯只住在 `cytrace-i18n` 的 `Catalog::render_cbom`，CLI 與 server 共用。
- `cargo build --no-default-features` 可建出不含 tokio 的純 CLI；CI 驗證這個組合。

## 3. 子程序編排

三個引擎都經 `cytrace-core::engine` 呼叫。`ScanEngine` trait 讓 server 的整合測試能注入 `FakeEngine`，
不需要引擎 binary。

### 3.1 版本釘選與取得

- 版本與 SHA256 釘在 `scripts/versions.env`：Syft、Grype、cbomkit-theia。theia 另釘 commit 與建置用的
  Go image digest。
- 子程序以名稱呼叫，經 `PATH` 尋找。交付包以 wrapper 把 `PATH` 指向包內 `bin/`，
  `make package` 對引擎版本設有 fail-hard 閘。容器映像內 PATH 已固定指向釘選版本。
  **不要假設任意 PATH 上的版本相容**：實測 syft 1.51 預設輸出 CycloneDX 1.7，
  會讓 grype 0.114 無法解讀（`.asp-fact-check.md` 2026-09-29）。
- theia 自源碼建置，不採用上游的 release binary（ADR-013 決策 1）。Linux 由 Dockerfile 的
  theia-builder stage 承接；Windows 版由 theia-builder-windows stage 以同一份源碼與參數交叉編譯（T911），
  SHA256 釘在 `THEIA_WINDOWS_AMD64_SHA256`，`package.ps1` 取用前比對，也作為 Release 資產發佈。

### 3.2 Syft／Grype

- `syft scan <target> -o cyclonedx-json -q`，輸出原樣落地為 `sbom.cdx.json`。
- 需要 SPDX 時（CLI `scan --spdx`；Web 服務模式一律）改為同一次執行多重輸出：
  `-o cyclonedx-json -o spdx-json=<暫存檔>`，兩種格式出自同一次編目（T919）。暫存檔名行程內唯一、
  用完即刪；SPDX 缺檔、不是 JSON 或缺 `spdxVersion` 時整次掃描失敗（fail-closed，取捨見 ADR-002 修訂節）。
- Grype 一律離線執行：`GRYPE_DB_AUTO_UPDATE=false`、`GRYPE_DB_VALIDATE_AGE=false`，
  DB 位置由 `GRYPE_DB_CACHE_DIR` 指定（ADR-003）。SBOM 先寫入暫存檔，再以 `sbom:<path>` 餵入，
  不走 stdin。
- DB 快照的真值取自 `grype db status`（`schemaVersion`／`built`）；取不到時填 sentinel `unavailable`，
  不填假值（ADR-009 修訂節）。

### 3.3 cbomkit-theia（ADR-013 決策 2、10）

- **輸入只接受本地路徑**（`engine::cbom_target`）：
  - 目錄 → `theia dir <path>`；docker-save tar 或 OCI layout → `theia image <path>`；
  - 一律先 `canonicalize` 成絕對路徑，並**實際開檔**驗證可讀。理由：theia 解析輸入失敗時，會把字串當成
    映像參照，回退去找 docker daemon 或 registry——實測會外連，或把本機同名映像當成目標；
  - 無法在本地判定的形態一律拒絕，不猜測。
- **環境隔離**：
  - `env_clear` 後只加回 `HOME`、`TMPDIR`、`PATH`；
  - 每次呼叫配一個**專用、可寫的 HOME**，在所有離開路徑上都會清理。HOME 不可寫時，theia 會把警告印進
    stdout、汙染 JSON；併發 job 共用 HOME 會互相干擾。
  - Windows 上另給 USERPROFILE、APPDATA、LOCALAPPDATA（皆為專用 HOME）與 TEMP、TMP，並帶回 SystemRoot、windir：
    Go 在 Windows 上以這些變數取代 HOME／TMPDIR（T911）。
- **逾時與抽乾**：
  - 預設逾時 600 秒，可用 `CYTRACE_CBOM_TIMEOUT_SECS` 覆寫，上限 86,400 秒；這個變數只供除錯，
    值不合法時退回預設；
  - stdout 與 stderr 以執行緒**併發抽乾**，避免 pipe 滿載造成死結；
  - 逾時即終止並收割子程序，不留 zombie；收尾抽乾另有寬限時間，抽不完視為失敗（`cbom.err.drain_timeout`）。
- **fail-closed**：
  - stdout 必須通過 `ensure_cbom_json`，空白、非 JSON 或不是 CycloneDX BOM 一律算失敗；
    **空輸出絕不等於「零資產」**；
  - `Ok(None)` 只代表引擎缺席（降級）。
- **未掃描計數**，三者分開記錄，因為處置方式不同：
  - `unscanned_unreadable`：權限不足，掃描前由 `unreadable_count` 自行清點；
  - `unscanned_oversize`：theia 自身略過大於 1 MiB 的檔案；
  - `unscanned_undetermined`：引擎自承偵測到、輸出卻沒有的資產；由 stderr 的計數與輸出比對而得。

### 3.4 錯誤

子程序找不到、非零退出、輸出不合法，一律回 `CytraceError`（§5）。CLI 對應退出碼 1，與門檻觸發的 2 區隔。

## 4. 資料模型（`ScanResult` schema v3）

```
ScanResult {
  schema_version: u32                       // 目前為 3（cytrace_types::SCHEMA_VERSION）
  meta: {
    target, generated_at,
    tool_versions { syft, grype, theia? },  // theia 僅在 CBOM 完成時填
    db_snapshot { version, built },         // grype db status 真值；取不到為 "unavailable"
    scan_identity?                          // 執行掃描的身分（ADR-013 決策 10）
  }
  components: [ Component { name, version, type, licenses[],       // → 軟體產品文件表
                           bom_ref?, purl?, locations[] } ]      // v3：來源（ADR-009 修訂）
  findings:   [ Vulnerability { id, severity, cvss?, component, fixed_version?, source,
                                component_version?, component_purl?, locations[] } ]
  summary:    { counts_by_severity, overall_risk }                // overall_risk = 最高等級
  crypto?: CryptoInventory {                                     // v1 檔無此欄位 → None
    status: NotRequested | EngineAbsent | Completed
          | { Failed: { reason_key, reason_detail? } },
    assets: [ CryptoAsset { name, asset_type, quantum, weak_key, location,
                            primitive?, key_size?, not_after? } ],
    unscanned_unreadable, unscanned_oversize, unscanned_undetermined
  }
}
```

- **`Severity`**：Critical／High／Medium／Low／Negligible／Unknown；對映與雙語標籤鍵見 ADR-006。
- **`CbomStatus`**：
  - 「沒開」「引擎不在」「失敗」「完成但 0 項」四種狀態必須可區分；
  - `reason_key` 是純 i18n 鍵，不夾散文；不可翻譯的細節（路徑、秒數）放在 `reason_detail`，由讀取端依語系渲染。
- **`QuantumStatus`** 與 **`weak_key`** 是兩條獨立的軸（`cytrace-core::quantum`；ADR-013 決策 6）：
  - RSA-4096 量子脆弱，但不是弱金鑰；
  - 規則移植自 cbomkit 的 `quantum_safe.rego`，再補上金鑰長度規則。
- **信任邊界**（NFR-09）：`assets` 只記存在、型別、長度、路徑等中繼資料，**不含金鑰內容**。
  約束範圍包含 `ScanResult`、報表、日誌，以及原樣落地的 `cbom.cdx.json`（ADR-013 決策 8）。
- **相容政策**（ADR-009）：
  - 新版 `cytrace report` 必須能重建舊版 JSON（v1 缺 `crypto` → `None`；v1、v2 缺 v3 的來源欄位 → 視為空，
    軟體產品文件表的位置欄以「—」呈現、弱點列不顯示位置行；皆由回歸測試釘住）；
  - 讀到比本版新的 `schema_version` 時會警告（`cli.schema_ahead`），因為 serde 會略過未知欄位。
- **來源欄位**（v3，ADR-009 修訂）：
  - `Component.locations` 取自 Syft 的 `syft:location:N:path`，依 N 排序，路徑相對於掃描根目錄。
  - `Vulnerability.locations` 依序取：Grype `artifact.locations` → `artifact.id` 等於元件的 `bom_ref`（命中即停）
    → 同 `purl` 的元件位置聯集（比對前做 percent-decode；artifact 帶 purl 時到此為止，避免混入其他生態系的同名套件）
    → artifact 沒有 purl 時才以同「名稱＋版本」的元件位置聯集；都對不到時留空，不猜測。
  - 報表各區段的「資料來源」列由 `meta.tool_versions` 與 `meta.db_snapshot` 組出，不另存欄位。
- **非決定性欄位**：`meta.generated_at` 等欄位在比對 golden baseline 前正規化（§9、ADR-008）。

## 5. 錯誤處理

- **兩種錯誤型別**：
  - core 一律回傳 `Result<T, CytraceError>`（thiserror）；
  - serve 啟動路徑與 CLI 的讀寫錯誤回傳 `Result<_, Localized>`（`cytrace_i18n::Localized { key, vars }`）。
- **`CytraceError` 的分類**：`Engine`（子程序）、`Parse`（JSON）、`Io`、`Config`、`DbMissing`、`Cbom`（純 i18n 鍵加不可翻譯細節）。
- **`CytraceError` 的 `Display` 是語系中立的 ASCII 診斷**（例如 `engine: …`），不給使用者看。
  使用者看到的文字，由呼叫端以 `i18n_key()` 加 `untranslatable_detail()` 依語系渲染：
  - `i18n_key()` 回傳 `server.err.{kind}` 或 `cbom.err.*`；
  - `untranslatable_detail()` 回傳路徑、子程序訊息等不翻譯的細節。

  server 的 job 錯誤與 CLI 的終端訊息共用同一組對應。
- **`Localized` 的鍵**：serve 啟動錯誤在 `server.startup.*`，執行期的 job 隔離與落盤警告在 `server.runtime.*`，
  CLI 的讀寫與解析錯誤在 `cli.err.*`（附檔案路徑）。
- **終端錯誤格式**：stderr 印一行 `cli.err.prefix`（「錯誤：…」或 “error: …”），內文依上述方式渲染。
  第三方函式庫與作業系統的訊息原樣附在細節裡，語言由該來源決定。
- **退出碼**（ADR-006）：

  | 碼 | 意義 |
  |---|---|
  | `0` | 正常；`--help`、`--version` |
  | `2` | `--fail-on` 或 `--fail-on-quantum-vulnerable` 觸發 |
  | `1` | 錯誤，含參數用法錯誤（含 `--fail-on` 值不合法）；量子閘門未取得完整結果（fail-closed） |

  - 同時成立時，1 優先於 2：「根本沒掃到」不得被「有弱點」遮蔽；
  - clap 預設以 2 表示用法錯誤，會與門檻撞號，因此自行處理解析結果、決定退出碼（`main` 的 `usage_error`）。

## 6. i18n

- **catalog**：
  - 共用 `locales/{zh-TW,en-US}.json`，前端、CLI、server 讀同一份；以鍵取訊息，缺鍵時退回 zh-TW；
  - 插值語法只有 `{{var}}`，以名稱全文比對，不去頭尾空白。
- **共用值契約**（ADR-004）：
  - 前端 react-i18next 與 Rust loader 共用鍵，也共用值的語意；
  - 共用命名空間禁用複數、context、nesting（`_one`／`_other`、`_male`、`$t()`）；
  - 佔位符名稱必須是單純識別字：react-i18next 會去頭尾空白，Rust 不會，寫成 `{{ addr }}` 兩邊會分歧。
- **操作者語言**（CLI 與 serve 的終端訊息）：
  - 來源優先序為 `--lang` > `CYTRACE_LANG` > zh-TW，所有子命令一致；`--lang` 是全域旗標，可放在子命令前後；
  - 正規化共用 `cytrace_i18n::lang_code`：`en*` → en-US、`zh*` → zh-TW，不分大小寫；
  - 優先序最高、有給值的來源不受支援時，以兩種語言各印一行警告後退回 zh-TW，不往下一個來源找；
    空白的環境變數視同未設；
  - serve 的啟動錯誤、關閉訊息、執行期警告都用操作者語言；
  - CLI 產出的報表（`report`／`run`／`batch`）也以操作者語言開啟（T918，見 §7「開啟語言」）。
- **API 回應的語言**不受操作者語言影響，依 ADR-011 §7 每個請求各自協商：`?lang=` > `Accept-Language` > zh-TW。
  Web 服務產出的報表以**送出掃描那次請求**協商出的語言開啟（T918）。
- **`--help` 與用法錯誤**（T914，`cytrace-cli/src/help.rs`）：
  - 語言在解析之前決定：先從 argv 預掃 `--lang`，再看 `CYTRACE_LANG`；
  - 說明文字住在 locale 的 `cli.help.*`，鍵由子命令名與參數 id 推導；以 clap builder 注入，區段標題、
    `--help`／`--version` 的說明也一併換掉；CLI 定義上不寫 doc 註解（i18n 棘輪會抓）；
  - 用法錯誤依 clap 的 `ErrorKind` 與錯誤附帶的 context 組成 `cli.usage.*` 訊息，第二行提示該子命令的
    `--help`；沒對映到的類型以 `cli.usage.other` 附上 clap 的英文原文；
  - 仍是英文的部分：usage 行裡的 `[OPTIONS]`、`<TARGET>` 等佔位符，以及沒對映到的錯誤類型的原文。
- **機械閘**（NFR-06）：
  - `scripts/i18n-check.py`：比對兩語的遞迴葉鍵，並確認程式碼引用的鍵都存在；
  - i18n 棘輪：全部 workspace 成員的生產碼不得有中文字面值，例外逐筆明列；
  - 插值對帳：程式碼給的變數必須等於兩語的佔位符；
  - CLI 端到端測試：兩種語言各跑一次，驗 stdout 與 stderr。

## 7. 報表內嵌與資料注入契約（ADR-009）

- **樣板**：
  - 前端以 Vite 單檔內聯建置，產物 `report-template.html` 放在 `crates/cytrace-report/assets/`，
    於編譯期內嵌；
  - 內嵌產物必須與 `frontend/src` 同步：locale 一改就要重產。CI 的「產物與源碼同步」步驟把關，
    本機的 make 目標不含這項檢查。
- **注入點**：樣板 head 內只有一個 sentinel `<!--CYTRACE_DATA-->`，替換為
  `<script id="cytrace-data" type="application/json">{…ScanResult…}</script>`。
  `type=application/json` 讓資料不受 `script-src` 管轄。
- **跳脫**：注入前把 `</` 換成 `<\/`，U+2028／U+2029 換成 ` `／` `；
  golden 測試驗證含 `</script>` 與 U+2028 的欄位能 round-trip。
- **開啟語言**（T918）：樣板根元素 `<html lang="zh-TW">` 必須恰好一個，產生時換成產生語言
  （CLI 的 `--lang`／`CYTRACE_LANG`；server 為送出掃描那次請求的語系），正規化同 `cytrace_i18n::lang_code`。
  前端 i18n 初始化讀它（`initialLang`），只接受 zh-TW／en-US，其餘 → zh-TW。這不是資料，不進 ScanResult。
- **前端讀取**：`JSON.parse(document.getElementById('cytrace-data').textContent)`。
  schema v2 的 `crypto` 欄位缺漏時視為未請求，所以 v1 JSON 照樣能渲染。
- **零外連**：字型本地子集化後內嵌；CSP 以 `connect-src 'none'` 擋外連，
  內聯腳本需要 `script-src 'unsafe-inline'`（ADR-005）。

## 8. 建置與交付

- **兩種交付形態**：
  - 離線安裝包（`make package` 產 Linux 包，`scripts/package.ps1` 產 Windows 包）：
    binary、釘選引擎、grype DB 快照、NOTICE、CHANGELOG、`SHA256SUMS`；
  - 容器映像（ADR-012，主要交付形態），見 docs/DOCKER.md。
- **建置目標**：Linux 為 `x86_64-unknown-linux-musl` 靜態連結；Windows 為 `x86_64-pc-windows-msvc`。
  TLS crypto provider 用 ring，兩個平台都能建，不需要 cmake。
- **釘選與可重現**：`rust-toolchain.toml`、`Cargo.lock`、`scripts/versions.env`（引擎版本與 SHA256）、
  grype DB 快照（ADR-007）。
- **建置期檢查**：`build.rs` 讀 `versions.env` 的 `THEIA_VERSION`；值有任何歧義就讓建置失敗。
  shell 端以相同規則對帳（`scripts/check-theia-version.sh`）。
- **供應鏈**：
  - `cargo deny check` 檢查授權、來源白名單、禁止清單、advisories，CI 每次抓最新的 RustSec DB（T913）；
  - NOTICE 由 `scripts/notice-parity-check.py` 對帳。

## 9. 測試策略

- **單元**：嚴重度對映、風險總評、閘門退出碼、解析器、量子判定、theia 輸入轉譯與輸出檢查。
- **golden baseline**（ADR-008）：在釘選的引擎版本下比對輸出快照，升級引擎才更新 baseline。
  非決定性欄位先正規化。
- **CLI 端到端**（`crates/cytrace-cli/tests`，unix）：
  - 以 shim 假扮引擎，驗退出碼語意（`gates.rs`）；
  - 驗操作者終端訊息的語言、無裸鍵、無殘留佔位符（`operator_lang.rs`）；
  - 含 serve 的實際起停，以及沒有 tty 時的 `hash-password`。
- **真引擎整合測試**（`make test-real-engine`，CI 獨立 job）：以真的 theia 跑各種輸入形態，驗 CBOM 的
  降級與失敗語意。
- **Web 服務**（`cytrace-server`）：以 `tower::ServiceExt::oneshot` 做整合測試，不開真實 socket，注入
  `FakeEngine`。涵蓋：
  - 認證生命週期、節流、CSRF；
  - 惡意壓縮包（zip-slip、symlink、bomb）、path traversal；
  - job 狀態機與重啟恢復；
  - 錯誤格式與語系協商、console 與 CSP。
- **前端**：typecheck；以 AST 檢查 console 的語系與 API 路徑規則；檢查 CBOM 成因渲染與 server 共用 fixture；
  零外連檢查。

## 10. Web 服務模式（`serve`；ADR-011／012）

- **執行模型**：
  - `serve` 自建 tokio runtime，`main()` 保持同步；
  - 掃描管線是同步的，經 `spawn_blocking` 隔離，以 `Semaphore` 限制併發；
  - 請求路徑禁止 panic（`panic=abort` 的 crash-only 設計，clippy 對 `unwrap_used` 設 deny）；
  - 停止訊號（Ctrl-C；unix 上另加 SIGTERM，即 `docker stop` 送的訊號，T915）在綁定位址之前就同步註冊，
    收到後優雅關閉（10 秒寬限）。容器裡 cytrace 是 PID 1，沒有 handler 時核心會忽略 SIGTERM。
- **設定**（`ServerConfig::resolve`）：
  - 優先序為旗標 > 環境變數 > 預設，函式本身是純函式；
  - 環境變數經 `Env` 收集：值不是 UTF-8 的變數只記名字，`resolve` **讀到它時**才回傳指名該變數的錯誤；
    旗標已覆寫的變數不會被讀。
- **認證**：
  - 單一管理帳號，密碼以 argon2id PHC 保存；缺少 `CYTRACE_ADMIN_PASSWORD_HASH` 時拒絕啟動；
  - session 存在記憶體，token 以 SHA-256 雜湊保存；cookie 設 HttpOnly 與 SameSite=Strict，啟用 TLS 時加 Secure；
    TTL 預設 12 小時；
  - 登入節流；CSRF 以自訂標頭防護，且不開 CORS。
- **TLS**：自帶 PEM，以 axum-server（`tls-rustls-no-provider`）加 ring 實作；不支援 ACME，零外連。
- **Job 模型**：
  - 沒有資料庫，`{data_dir}/jobs/<id>/` 的檔案系統就是狀態真相；`job.json` 以暫存檔加 rename 原子落盤；
  - 重啟時，非終態的 job 標為 `interrupted`；損毀的記錄改名為 `.corrupt` 隔離，改名成功才回報。
- **輸入**：
  - 上傳：multipart 串流，zip／tar／tar.gz 有三道解壓防護。解開後依內容決定 Syft 的目標：docker-save →
    `docker-archive:<原始 tar>`（gzip 先解壓）；只有 OCI layout → `oci-dir:`；其餘 → `dir:`（ADR-011 修訂，#49）；
  - 掛載目錄白名單：先做語彙檢查，再以 canonicalize 加前綴驗證擋 symlink 逃逸。目標是檔案（例如映像 tar）時
    不加 `dir:`，交給 Syft 自動辨識；目錄是 OCI layout 時給 `oci-dir:`，其餘目錄 `dir:`（ADR-011 修訂，#49）。
- **API**：
  - 路徑：`/api/v1` 下的 session、targets、jobs、upload、report、result、artifacts、version，加上 `/healthz`；
  - 產物 `GET /jobs/{id}/artifacts/{kind}`：`sbom`（CycloneDX）、`spdx`、`grype`、`cbom`，以附件回應
    （`Content-Disposition` 帶檔名）；單筆 `GET /jobs/{id}` 另附 `artifacts`，列出實際存在的產物，console 據此顯示下載連結；
  - 錯誤格式為 `{error:{kind,i18n_key,message,detail}}`。`message` 依請求語系渲染，`detail` 是不翻譯的原始資訊；
    job 失敗的 `message` 走與 console 共用 fixture 的退回鏈。
  - 路徑違規回 403，原因碼與請求的 root、path 附在 `detail`；伺服器端不另記稽核 log（ADR-011 修訂節，T916）。
- **前端 console**：
  - 與報表樣板各自一份 Vite config，採 hash routing，以 rust-embed 內嵌；
  - CSP header 硬化；report 端點自帶較寬的 CSP，不會被覆蓋。
- **交付**：容器為主，見 docs/DOCKER.md 與 DELIVERY_SOP §7。
