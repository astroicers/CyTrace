# 變更記錄（CHANGELOG）

> 對象：air-gapped 場域的操作員與稽核人員。本檔隨交付包散布
>（`make package` 會收入包內），是離線環境唯一的版本變更說明。
> 格式依 [Keep a Changelog](https://keepachangelog.com/zh-TW/1.1.0/)；版本依 SemVer。

## [Unreleased]

### 新增

- Web 控制台 API：掃描任務失敗時，`GET /api/v1/jobs/{id}` 與任務列表回應的 `error`
  另附依請求語系（`?lang=` 或 `Accept-Language`）渲染的 `message`，供 CI 腳本等非控制台
  用戶端直接使用。落盤的任務記錄不變。控制台與 API 對同一筆失敗顯示相同的說明。

### 修正

- Web 控制台 API 的錯誤訊息一律依請求語系渲染（T909）。先前部分錯誤說明是硬編碼中文；
  請求格式錯誤（壞 JSON、查詢參數、路徑）回英文純文字，不符 `{"error":{…}}` 格式。
  現一律回 JSON 錯誤格式；超過大小上限仍回 413，伺服器自身錯誤回 500。
  **狀態碼變更**：`Content-Type` 不符（原 415）與 JSON 欄位型別錯誤（原 422）現統一回
  400（`kind` 為 `validation`）；以 415／422 判斷錯誤的腳本需改看 400 與 `kind`。
- 路徑存在但 HTTP 方法不符時（含 `/healthz`），回 JSON 405（附 `Allow` 標頭）；先前回應內容為空。
  未登入時受保護路徑仍先回 401。
- Web 控制台送出的語系改為**畫面實際使用的語系**。先前依瀏覽器語系，英文介面可能收到
  中文錯誤訊息；報表／結果連結現在也帶語系；時間依介面語系格式化。
- GitHub Release 說明改由本檔產生。v0.3.0 的 Release 頁曾被映像附掛步驟整份覆蓋，
  已復原並於頁首註明更正。
- 交付 SOP：Windows 打包指令補上 `-WithoutCbom`（Windows 版 CBOM 引擎尚未就緒，T911）；
  原指令照做會被打包腳本擋下。

### 變更

- `scripts/versions.env` 中，註解以外**只准有一行**提到 `THEIA_VERSION`，且逐字寫成
  `THEIA_VERSION=1.1.2` 這種形式（不縮排、不加 `export`、不加引號或行內註解、只收正式版號），
  檔案須為 UTF-8，否則建置與打包直接失敗。先前重複、`export` 再賦值或帶引號時，報表與 NOTICE 上的引擎版本
  會靜默不一致。

## [0.3.0] - 2026-09-30

### 新增

- **CBOM 密碼學資產盤點**（ADR-013 / M9）：`cytrace run|scan|batch --cbom`
  （**預設關閉**）。封裝第三個引擎 **CBOMkit-theia v1.1.2**（Apache-2.0，
  自源碼可重現建置、SHA256 釘死），盤點掃描目標內的 X.509 憑證、公私鑰與
  演算法，判定量子脆弱性（規則移植自 cbomkit `quantum_safe.rego`）。
- `--fail-on-quantum-vulnerable` 閘門，**fail-closed**（「沒掃到 ≠ 通過」）：
  已偵測到量子脆弱或無法判定的資產 → exit 2（**優先於**清單不完整——漏掃只會
  讓實況更糟，不得遮蔽已知脆弱）；引擎缺席／執行失敗／無脆弱但清單不完整 →
  exit 1；掃描完成且乾淨 → exit 0。
- 報表新增 `#crypto` 區段：資產表（演算法／金鑰長度／量子狀態／位置）、
  三類漏掃計數顯性揭露（權限不可讀／超過引擎 1 MiB 門檻／引擎自承未建模）、
  失敗成因依語系渲染。
- `scan --cbom` 另落地 `cbom.cdx.json`（CycloneDX 1.6，通過離線 schema 驗證）。
- Web 控制台：掃描任務可勾選 CBOM；失敗成因依請求語系顯示。
- 報表封面新增**掃描身分**（執行 uid）與 **CBOM 引擎版本**（NFR-03 稽核欄位）。
- 環境變數 `CYTRACE_CBOM_TIMEOUT_SECS`（1–86400，預設 600；**越界或非數字
  靜默回退預設**；刻意無「無限制」選項——目標含具名管線時無逾時會永久掛死）。

### 修正

- **報表的 DB 快照欄位改為真值**：先前硬編碼 `snapshot` / `unknown`，
  SOP §5 宣稱的「DB 時效稽核」實質不存在。現取自 `grype db status`
  （版本 + 建置時間）；取不到時顯示明確的「無法取得」而非假值。
- 打包腳本 fail-hard 語意補齊：build 機引擎版本不符 `versions.env` 釘選版、
  或 grype DB 缺失時，打包直接失敗（先前會靜默出「完整」包）。
- GitHub Release 資產修正：容器映像校驗檔改名 `SHA256SUMS-image`
  （先前與執行檔的 `SHA256SUMS` 同名互蓋，v0.2.x 兩版的 image tar 均無校驗和）。
- Docker 發布順序修正：**冒煙通過才 push**（先前 push 先行，冒煙失敗時
  壞 image 已公開）。
- Release 管線加版本一致閘：tag 與 `Cargo.toml` 不符即擋下發布
  （v0.2.0 / v0.2.1 的執行檔均自報 0.1.0，本版起機械攔截）。

### 變更

- `ScanResult` schema **1 → 2**：新增 `crypto` 區段（`#[serde(default)]`，
  v1 報表仍可以 `cytrace report` 重建）。
- 交付包內容：新增 `bin/cbomkit-theia` 與 NOTICE 對應段（gitleaks MIT、
  MPL-2.0 三項相依標示；Apache-2.0 §4(b) 未修改聲明）。
  刻意不含 CBOM 引擎的包以 `WITHOUT_CBOM=1` 顯式產生。

### 已知限制

- CBOM 為檔案系統／映像層盤點；**原始碼層**演算法辨識不在本版（無合規離線方案）。
- 引擎對 >1 MiB 檔案跳掃（如大型 CA bundle）；以「未掃描」計數揭露並由閘門承接。
- OpenSSH 格式私鑰引擎偵測到但不建模；計入「引擎自承未建模」計數。
- server API 錯誤 detail 尚有少量硬編碼中文（T909，下版處理）。
- Windows 交付包**不含 CBOM 引擎**（`--cbom` 降級為「未盤點」；T911），且尚未於實機場域驗證。

## [0.2.1] - 2026-07-04

- 報表「列印 / 存 PDF」按鈕 + 列印 CSS（ADR-005 瀏覽器列印替代）。
- Docker：image SBOM 改用 `syft --user 0:0` 掃 tar（修 0-byte 上傳）。
- ⚠️ 本版執行檔自報版本為 0.1.0（版本失同步，0.3.0 起以 CI 閘攔截）。

## [0.2.0] - 2026-07-03

- Web 控制台（`cytrace serve`，ADR-011）：上傳掃描、任務佇列、報表下載。
- 容器交付（ADR-012）：GHCR image + 離線 tar。
- ⚠️ 同上版本失同步注記。

## [0.1.0] - 2026-06

- 首版：Syft SBOM + Grype CVE 比對，離線單檔 HTML 報表，musl 靜態 binary。
