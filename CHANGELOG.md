# 變更記錄（CHANGELOG）

> 對象：air-gapped 場域的操作員與稽核人員。本檔隨交付包散布
>（`make package` 會收入包內），是離線環境唯一的版本變更說明。
> 格式依 [Keep a Changelog](https://keepachangelog.com/zh-TW/1.1.0/)；版本依 SemVer。

## [Unreleased]

### 修正

- `scripts/package.sh` 在缺 musl 的 C 編譯器時會在建置中途默默結束；現在會先檢查並提示安裝 `musl-tools`，
  建置失敗時也會印出錯誤內容（T920）。
- Windows 打包腳本 `package.ps1` 補上與 Linux 版對等的 minisign 簽章步驟：`minisign` 在 PATH 上且設了
  `CYTRACE_MINISIGN_SECKEY` 時，對 `SHA256SUMS` 簽章（T920）。

## [0.4.0] - 2026-10-05

### 新增

- Windows 交付包內含 CBOM 引擎 `cbomkit-theia.exe`（T911），`--cbom` 在 Windows 上也能盤點密碼學資產。
  引擎同樣自源碼建置：與 Linux 版同一份釘選源碼、同一組參數交叉編譯，產物 SHA256 釘在
  `versions.env`；打包腳本取用前比對，不符即中止。GitHub Release 另附 `cbomkit-theia-windows-amd64.exe`
  供打包取用，取得方式見交付 SOP §2。
- `--help` 與參數用法錯誤依指定語言輸出（T914）：說明文字、區段標題、錯誤訊息都跟著 `--lang`／
  `CYTRACE_LANG`；錯誤訊息第二行提示該子命令的 `--help`。usage 行裡的 `[OPTIONS]`、`<TARGET>` 等佔位符維持原樣。
- Web 控制台 API：掃描任務失敗時，`GET /api/v1/jobs/{id}` 與任務列表回應的 `error`
  另附依請求語系（`?lang=` 或 `Accept-Language`）渲染的 `message`，供 CI 腳本等非控制台
  用戶端直接使用。落盤的任務記錄不變。控制台與 API 對同一筆失敗顯示相同的說明。
- 終端機訊息的語言可用環境變數 `CYTRACE_LANG` 設定（`--lang` 優先，皆無則 zh-TW）。
  容器加 `-e CYTRACE_LANG=en-US` 即可讓日誌改為英文；控制台與 API 的語言不受影響。
  語言值不支援時，以中英兩種語言各印一行警告後改用 zh-TW（先前不提示，直接改用 zh-TW）。

### 變更

- 移除 `cytrace help <子命令>` 的寫法，請改用 `cytrace <子命令> --help`（T914；說明在地化後由我方提供 `--help`）。
- **退出碼**：參數打錯（未知旗標、缺少必要參數）的退出碼由 `2` 改為 `1`。現在 `2` 只代表
  `--fail-on` 或 `--fail-on-quantum-vulnerable` 觸發；先前以退出碼 2 判斷門檻的 CI 腳本，
  會把參數打錯誤判為門檻觸發。`--help`、`--version` 仍為 `0`。
- `--fail-on` 的值必須是 critical／high／medium／low／negligible／unknown（大小寫不拘），
  否則以 `1` 結束。先前任何字串都被接受，打錯字（如 `hgih`）會被當成最低的 unknown，
  等於「有任何弱點就以 2 結束」。CLI 與 Web API 現在接受同一組值；比對方式不同：CLI 不分大小寫，
  API 只收小寫。空值：CLI 拒收；API 的上傳（multipart）先去頭尾空白、空值視為未設定，
  JSON 的 `POST /api/v1/jobs` 則拒收空字串。
- 錯誤前綴由固定的「錯誤 / error:」改為依語言擇一（「錯誤：」或 `error:`）；讀寫檔失敗的
  訊息附上檔案路徑。以字串比對錯誤前綴的腳本需調整。
- `scripts/versions.env` 中，註解以外**只准有一行**提到 `THEIA_VERSION`，且逐字寫成
  `THEIA_VERSION=1.1.2` 這種形式（不縮排、不加 `export`、不加引號或行內註解、只收正式版號），
  檔案須為 UTF-8，否則建置與打包直接失敗。先前重複、`export` 再賦值或帶引號時，報表與 NOTICE 上的引擎版本
  會靜默不一致。

### 修正

- 容器 `docker stop` 時優雅關閉（T915）。先前服務只處理 Ctrl-C；容器裡它是 PID 1，`docker stop` 送的
  SIGTERM 被直接忽略，要等逾時（預設 10 秒）後被強制終止。現在收到 SIGTERM 即停止接受新連線並正常結束。
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
- 終端機訊息依指定語言輸出（T912）。先前在 `--lang en-US` 下仍是中文的有：
  serve 的啟動錯誤（缺管理密碼、位址不合法、TLS 憑證載入失敗、資料目錄無法建立）、
  任務記錄損毀與寫入失敗的警告、`scan --cbom` 的引擎錯誤，以及錯誤前綴後的說明。
- serve 啟動時若損毀的任務記錄**隔離失敗**，現在如實回報並保留在原處，下次啟動會再試；
  先前不論成敗都印「已隔離」。缺少 job.json 與 job.json 內容損毀分開說明。
  重啟時把未完成的任務標為中斷、寫回卻失敗時，先前不留訊息，現在會印出警告。
- 監聽位址不合法時，訊息指出值來自 `--bind` 還是 `CYTRACE_BIND`；先前一律寫 `CYTRACE_BIND`。
- 環境中任一變數不是合法 UTF-8 時，`serve` 會當掉（退出碼非 1、訊息未在地化）。現在只有 serve
  實際要讀的變數（例如 `CYTRACE_DATA_DIR`、`GRYPE_DB_CACHE_DIR`）值不是 UTF-8 時才以 `1` 結束並
  指名該變數；已由命令列旗標覆寫的（如給了 `--data-dir`）、以及不屬於服務設定的變數
  （如 `CYTRACE_LANG`）不受影響。
  `health` 讀 `CYTRACE_BIND` 時亦同。
- serve 在印出監聽位址之前就先掛好 Ctrl-C 的處理；先前剛啟動就按下 Ctrl-C，可能直接中止
  （未優雅關閉）或被忽略。
- 文件中以容器產生管理密碼的指令補上 `-it`（`docker run --rm -it <image> hash-password`）。
  少了 `-t` 時密碼無法輸入，指令必定失敗。

### 安全性

- 升級有安全通報的相依套件（T913；離線交付包內的 `cytrace` 隨之更新）：
  - `rustls` 0.23.41 → 0.23.45（RUSTSEC-2026-0285：TLS 1.3 握手訊息跨加密層級被接受；影響 Web 服務模式的 HTTPS）；
  - `h2` 0.4.15 → 0.4.16（RUSTSEC-2026-0258：空 DATA frame 可耗盡資源）；
  - `anyhow` 1.0.102 → 1.0.103（RUSTSEC-2026-0190：unsound）；
  - `axum-server` 0.7 → 0.8：不再依賴已停止維護的 `rustls-pemfile`（RUSTSEC-2025-0134）。
    Web 服務的 TLS 行為不變（實測 TLS 1.3、Ctrl-C 優雅關閉、憑證格式錯誤時拒絕啟動）；
    憑證檔格式錯誤時，錯誤訊息細節的措辭可能與先前不同。
- CI 新增依賴安全通報檢查（`cargo deny check advisories`），先前未檢查。

### 已知限制

- CBOM 為檔案系統／映像層盤點；**原始碼層**演算法辨識不在本版（無合規離線方案）。
- 引擎對 >1 MiB 檔案跳掃（如大型 CA bundle）；以「未掃描」計數揭露並由閘門承接。
- OpenSSH 格式私鑰引擎偵測到但不建模；計入「引擎自承未建模」計數。
- Windows 交付包的 CBOM 引擎已在 GitHub 的 Windows runner 上實際執行驗證，**尚未於場域 Windows 機器驗證**。
- `--help` 用法行裡的 `[OPTIONS]`、`<TARGET>` 等佔位符，以及少數未逐一翻譯的參數錯誤類型，仍為英文。
- `docker stop`（或 Ctrl-C）時，進行中的掃描不會等它跑完；重啟後該任務標為「中斷」，可重新送出。

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
