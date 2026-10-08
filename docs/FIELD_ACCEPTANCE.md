# CyTrace 場域驗收清單

> 用途：在**真正斷網的目標機**上，把一份交付包從驗章走到產出報表，逐項確認可用。
> 列印後在現場逐項打勾、填寫，結束後由雙方簽核。
> 依據：[DELIVERY_SOP.md](DELIVERY_SOP.md)（以下簡稱 SOP）、[DOCKER.md](DOCKER.md)、[SRS.md](SRS.md)。
> 本清單只用 SOP 已寫明的指令；兩者不一致時以 SOP 為準，並在第 9 節記下差異。

## 0. 基本資料

| 項目 | 填寫 |
|---|---|
| 驗收日期 | |
| 單位／地點 | |
| 執行人 | |
| 見證人 | |
| 交付版本（驗收單上的版本） | |
| 平台 | ☐ Linux x86_64　☐ Windows x86_64　☐ 容器（第 8 節） |
| 目標機作業系統與版本 | |
| 檢視報表用的瀏覽器與版本 | |

## 1. 事前準備（進場前備妥）

- [ ] **交付驗收單（紙本）**，上面抄有交付公鑰字串與金鑰 ID。須與交付媒體**分開**遞交（SOP §3）。
      公鑰字串應為：`RWQOsSIYb8xaBZvkvmUpX/X8RzYFHPVNujqCGCsg53ytFOc+btCvTlFX`，金鑰 ID `055ACC6F1822B10E`。
- [ ] **目標機上的 `minisign`**。安裝包**不附**驗章工具，須依場域核可流程另行攜入。
      來源與版本：________________
- [ ] **交付媒體**：Linux 為 `cytrace-<版本>/`，Windows 為 `cytrace-<版本>-windows/`。
      DB 快照約 3 GB（2026-10 實測 v6.1.10 解開後 3.0 GB，會隨時間成長），請確認媒體容量與複製時間。
- [ ] **掃描目標 A**：場域內一個實際的原始碼目錄或系統目錄，預期含有已知弱點的依賴。
      路徑：________________
- [ ] **掃描目標 B**：含憑證或金鑰檔的目錄，供第 5 節 CBOM 檢查用。
      Windows 首次交付**必做**（SOP §6：Windows 版 CBOM 引擎尚未在場域機器驗證過）。
      路徑：________________
- [ ] **確認目標機已斷網**，並寫下確認方式：________________

## 2. 驗章與完整性（SOP §3）

在安裝包目錄內執行。**任一項失敗即停止驗收**，到第 9 節記錄，不要繼續安裝。

**Linux**

```bash
minisign -Vm SHA256SUMS -P '<驗收單上的公鑰字串>'
sha256sum -c SHA256SUMS
```

**Windows**（PowerShell，在安裝包目錄內）

```powershell
.\minisign.exe -Vm SHA256SUMS -P '<驗收單上的公鑰字串>'   # minisign.exe 放的位置依實際攜入處調整
$bad = 0
foreach ($line in Get-Content .\SHA256SUMS) {
  $hash, $path = $line -split '  ', 2
  if (-not (Test-Path -LiteralPath $path) -or
      (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne $hash) {
    Write-Host "MISMATCH: $path"; $bad++
  }
}
if ($bad) { Write-Host "FAILED: $bad file(s)" } else { Write-Host "OK: all files match" }
```

- [ ] 公鑰字串是**照驗收單輸入**的，沒有使用交付媒體裡附的任何公鑰。
- [ ] minisign 顯示 `Signature and comment signature verified`。
- [ ] 完整性檢查全部通過：Linux 每行 `OK`、退出碼 0；Windows 最後一行為 `OK: all files match`。
- [ ] 安裝包結構與 SOP §1 相符：`bin/` 內有 cytrace、syft、grype、cbomkit-theia，另有 `db/`、
      `cytrace.sbom.cdx.json`、`NOTICE`、`CHANGELOG.md`、`cytrace-offline`（Windows 為 `.ps1`）。

## 3. 基本執行

以下一律透過 wrapper 執行。wrapper 會固定使用包內引擎與 DB，並強制離線。

- Linux：`./cytrace-offline <子命令> …`
- Windows：`.\cytrace-offline.ps1 <子命令> …`
  若執行原則擋下 `.ps1`，改用 `powershell -ExecutionPolicy Bypass -File .\cytrace-offline.ps1 <子命令> …`。

檢查項目：

- [ ] `cytrace-offline --version` 顯示 `cytrace <版本>`，與驗收單相符。
- [ ] `cytrace-offline --help` 以繁體中文顯示子命令清單（run、batch、scan、report、serve、hash-password、health）。
- [ ] `cytrace-offline --lang en-US --help` 改以英文顯示。
- [ ] 打錯參數（例如 `cytrace-offline run`，不給目標）會顯示錯誤訊息，退出碼為 **1**。

查退出碼的方法：Linux 用 `echo $?`，Windows 用 `$LASTEXITCODE`。

## 4. 掃描與報表（FR-001～006、FR-010）

```bash
./cytrace-offline run <掃描目標 A> --fail-on high
```

- [ ] 掃描完成，產出 `<目標名>.report.html`。耗時：______
- [ ] 退出碼符合結果：有 high 以上的弱點時為 **2**，沒有時為 **0**。實際退出碼：______
- [ ] 掃描期間**沒有任何對外連線嘗試**。以場域既有手段確認，例如防火牆或網路監控紀錄。確認方式：________________

用瀏覽器開啟報表，逐區塊確認：

- [ ] **封面**：受測目標、產生時間、工具版本（Syft／Grype／CBOMkit-theia）、掃描身分都有顯示。
- [ ] **DB 快照版本與日期**有實際值，**沒有顯示「無法取得 DB 快照資訊（時效稽核不可用）」**。
      快照日期：______（漏洞資料的時效以此為準）
- [ ] **風險總評**：總評等級與各嚴重度的計數都有顯示。
- [ ] **弱點明細**：可依嚴重度篩選。抽查一筆 CVE 的元件與版本是否合理：______
- [ ] **軟體產品文件表**：列出元件名稱、版本、類型與授權。
- [ ] **附註**含免責句「本報表為產出/核發之依賴風險報表，非滲透測試或資安檢測，不得作為滲透測試結論引用。」（NFR-10）
- [ ] 報表內切換語言可在中英之間切換；以 `--lang en-US` 產生的報表預設以英文開啟。
- [ ] 開啟報表時**沒有對外請求**。可在瀏覽器開發者工具的「網路」分頁確認全部為本地資源（NFR-01）。
- [ ] 把報表檔複製到另一台離線電腦，仍能完整開啟（單檔、自包含）。
- [ ] 列印或存成 PDF 的版面可接受（PDF 驗收以瀏覽器列印替代，見 SRS §6）。

**只產 SBOM**：

```bash
./cytrace-offline scan <掃描目標 A> --spdx
```

- [ ] 產出 `sbom.cdx.json`、`sbom.spdx.json`、`grype.json`，三者都是可讀的 JSON。

**批次**：

```bash
./cytrace-offline batch <目標 A> <目標 B> --fail-on high
```

- [ ] 兩個目標各產出一份報表；退出碼取兩個目標中最嚴重者。

## 5. 密碼學資產盤點（FR-011、FR-012）

```bash
./cytrace-offline run <掃描目標 B> --cbom
```

- [ ] 報表出現「密碼學資產」區段，狀態為**完成**，不是「引擎缺席」或「失敗」。
- [ ] 摘要計數（總數／量子脆弱／弱金鑰／過期）合理；資產表**不含金鑰內容**本身。
- [ ] 加上 `--fail-on-quantum-vulnerable` 再跑一次：有量子脆弱資產（如 RSA、ECC）時退出碼為 **2**。
- [ ] Windows：以上三項在場域 Windows 機器上實際通過（SOP §6 的首次驗證）。

## 6. 可及性抽查（NFR-08）

只用鍵盤操作報表。本輪沒有重跑自動化稽核，這一節是人工抽查。

- [ ] 用 Tab 能依序走到篩選、語言切換、主題切換、列印等所有控制項；焦點框清楚可見。
- [ ] 亮色與暗色主題下，正文都清楚可讀。

## 7. 漏洞 DB 更新演練（SOP §5，選做）

- [ ] 以核可流程攜入新的 DB 快照，替換 `db/` 後再跑一次第 4 節的掃描。
- [ ] 報表上的 DB 快照日期隨之更新。新日期：______

## 8. 容器交付（交付含容器時才做；SOP §7、DOCKER.md）

**載入映像**：

```bash
minisign -Vm cytrace-vX.Y.Z-image.tar -P '<驗收單上的公鑰字串>'
sha256sum -c SHA256SUMS-image
docker load -i cytrace-vX.Y.Z-image.tar
docker tag ghcr.io/astroicers/cytrace:X.Y.Z ghcr.io/astroicers/cytrace:latest
docker images --digests
```

- [ ] 驗章與完整性都通過。注意映像的校驗檔是 `SHA256SUMS-image`，不是執行檔那份 `SHA256SUMS`。
- [ ] 載入後記下 image ID：________________
      `docker load` 不會還原 registry digest，所以記的是 image ID（SOP §7.2）。

**起站**：

- [ ] `docker run --rm -it ghcr.io/astroicers/cytrace:latest hash-password` 產出 `$argon2id$` 開頭的字串。
- [ ] 依 DOCKER.md 起站，`/db` 掛入 DB 快照、`/certs` 掛入場域 PKI 簽發的憑證，啟用 TLS。
      瀏覽器以 HTTPS 開啟登入頁，憑證受信任。
- [ ] 以管理帳號登入控制台，介面依瀏覽器語系以中文或英文顯示。

**掃描**：

- [ ] **掛載目標**（`/scan-targets` 搭配 `CYTRACE_SCAN_ROOTS`）送出掃描，完成後可線上檢視報表，也能下載 SBOM（CycloneDX、SPDX）與 Grype 結果。
- [ ] **上傳掃描**（zip 或 tar）完成後，伺服器上該工作的 `input/` 已不存在（NFR-09；預設 `CYTRACE_KEEP_INPUT=false`）。
      檢查路徑：`<data volume>/jobs/<job id>/input`
- [ ] **映像掃描**：用 `docker save <映像> -o img.tar` 匯出一個場域內的映像，分別以上傳與掛載兩種方式掃描。兩者的
      元件數都應大於 0，且與 CLI `cytrace-offline run docker-archive:img.tar` 的結果相同。
      一個映像一個 tar；gzip 壓縮的映像請用上傳方式（掛載不支援）。其他限制見 ADR-011 修訂節。
- [ ] **不外露主機路徑**（NFR-09，ADR-009 修訂）：任選一個上傳與一個掛載的工作，下載報表、ScanResult、SBOM（CycloneDX、
      SPDX）、Grype 與 CBOM 產物。逐一搜尋 `<資料目錄>/jobs`（容器部署為 `/data/jobs`）與掃描根的路徑
      （容器部署為 `/scan-targets`），都應找不到；報表封面的「受測目標」應顯示 `upload:<檔名>` 或 `mounted:<root>/<path>`。
      （Grype 產物內記錄的漏洞 DB 安裝路徑，例如 `/db`，屬於預期，見 ADR-009 修訂。）
- [ ] （選做）從控制台下載 ScanResult，在另一台機器以 `cytrace report <檔案>` 重建報表，內容一致。

**停機與降級**：

- [ ] `docker stop` 在約 10 秒內結束；重啟後，原本執行中的工作顯示為 `interrupted`，可以重新送出。
- [ ] （選做）不掛 `/db` 起站：仍可登入，但掃描回報 DB 缺失，`/api/v1/version` 的 `db.present` 為 `false`。

## 9. 偏差與問題紀錄

| # | 節次／項目 | 現象 | 影響 | 處置 |
|---|---|---|---|---|
| 1 | | | | |
| 2 | | | | |
| 3 | | | | |

## 10. 結論與簽核

- ☐ **通過**：所有必做項目都打勾，沒有未處置的偏差。
- ☐ **有條件通過**：偏差已記錄，並議定處置與期限。
- ☐ **不通過**：原因見第 9 節。

| 角色 | 姓名 | 簽名 | 日期 |
|---|---|---|---|
| 交付方 | | | |
| 驗收方 | | | |
