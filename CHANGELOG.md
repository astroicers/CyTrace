# 變更記錄（CHANGELOG）

> 對象：air-gapped 場域的操作員與稽核人員。本檔隨交付包散布
>（`make package` 會收入包內），是離線環境唯一的版本變更說明。
> 格式依 [Keep a Changelog](https://keepachangelog.com/zh-TW/1.1.0/)；版本依 SemVer。

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
- Windows 交付包經 CI 冒煙驗證，尚未於實機場域驗證。

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
