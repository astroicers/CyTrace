# CyTrace 離線交付與更新 SOP

> 對應 ADR-003（離線漏洞 DB）、ADR-007（封裝/簽章/信任錨）。場域：軍用地端、無網際網路。

## 1. 安裝包內容（單一可攜目錄）

```
cytrace-<版本>/
├── bin/
│   ├── cytrace            # musl 靜態 binary（零 runtime 依賴）
│   ├── syft               # 釘選版（產 SBOM）
│   ├── grype              # 釘選版（比對 CVE）
│   └── cbomkit-theia      # 釘選版（密碼學資產盤點；自源碼建置，ADR-013）
├── db/                    # grype 漏洞 DB 離線快照（含建立日期）
├── cytrace.sbom.cdx.json  # CyTrace 自產 SBOM（dogfooding，FR-009）
├── NOTICE                 # 第三方授權（Syft/Grype/theia 本體 Apache-2.0；theia 相依另含 MIT/MPL-2.0）
├── cytrace-offline        # 離線執行 wrapper（設定 PATH 與 GRYPE_DB_CACHE_DIR）
├── CHANGELOG.md           # 版本變更說明（air-gapped 場域唯一來源）
├── SHA256SUMS             # 完整性
└── SHA256SUMS.minisig     # 真實性（minisign detached 簽章）
```

Windows 包結構相同，檔名為 `cytrace.exe`、`syft.exe`、`grype.exe`、`cbomkit-theia.exe`，wrapper 為 `cytrace-offline.ps1`，
目錄名為 `cytrace-<版本>-windows`。

## 2. 產生安裝包（有網段 / build 機）

**前置（Linux，一次性）**：CBOM 引擎自源碼可重現建置（ADR-013 決策 1；需 Docker）：
```bash
scripts/build-theia.sh   # 產 cbomkit-theia 並驗 SHA256（versions.env 釘死）
```
沒有它 `make package` 會 fail-hard（刻意不含 CBOM 時以 `WITHOUT_CBOM=1` 顯式豁免）。
build 機的 syft/grype **版本必須等於 versions.env 釘選版**，否則打包直接失敗——
環境漂移的引擎（如 syft 1.51 輸出 CycloneDX 1.7）會讓場域的 grype 整條讀不懂。

```bash
make package            # 或 scripts/package.sh <輸出目錄>
```
**Windows 版**（在 Windows build 機，先 `grype db update`）：

CBOM 引擎的 Windows 版同樣自源碼建置（T911），二擇一取得後放到 `dist\cbomkit-theia.exe`：
- 取我方 GitHub Release 的資產 `cbomkit-theia-windows-amd64.exe`（release workflow 交叉編譯並驗 SHA256），
  改名為 `cbomkit-theia.exe`；
- 或在有 Docker 的 Linux 機：`scripts/build-theia.sh dist windows`，再把 `dist/cbomkit-theia.exe` 帶過來。

```powershell
pwsh scripts/package.ps1   # 產 delivery\cytrace-<版本>-windows\
```
腳本取用前比對 `versions.env` 的 `THEIA_WINDOWS_AMD64_SHA256`，不符即中止。缺檔時腳本 fail-hard；
刻意不含 CBOM 引擎時以 `-WithoutCbom` 顯式說出來（此包的 `--cbom` 降級為「未盤點」，
不影響 SBOM 與弱點比對）。
兩支腳本的步驟相同：build 靜態 binary（Linux：musl；Windows：msvc 靜態 CRT）→ 收集釘選引擎（syft／grype 核對自報版本，
CBOM 引擎比對 SHA256）與 grype DB 快照 → 產自產 SBOM → 寫 NOTICE（依包內實際有無 CBOM 引擎）→ 收入 CHANGELOG →
算 SHA256SUMS。minisign 簽章見 §3（在交付工作站以受管金鑰執行，不在 CI）。

## 3. 簽章與離線信任錨（ADR-007 / NEW-3）

- 簽章工具：**minisign**（detached，SHA-256）。
- **交付公鑰**（金鑰 ID `055ACC6F1822B10E`；檔案為 repo 的 `keys/cytrace.pub`）：

  ```
  RWQOsSIYb8xaBZvkvmUpX/X8RzYFHPVNujqCGCsg53ytFOc+btCvTlFX
  ```

  > 本字串與 `keys/cytrace.pub` 由 `scripts/pubkey-check.py` 在 CI 對帳，抄錯一個字元即紅。
- **私鑰**：只在交付工作站的 `~/.minisign/cytrace.key`，以密碼保護（scrypt），不進 repo、不進 CI。
  私鑰與密碼另行備份；遺失時改用新金鑰簽章，並須重新以帶外方式交付新公鑰。
- **簽章**（打包時自動，簽章時會詢問私鑰密碼）：
  `CYTRACE_MINISIGN_SECKEY=~/.minisign/cytrace.key scripts/package.sh`
  （Windows：`$env:CYTRACE_MINISIGN_SECKEY=...` 後跑 `package.ps1`）。產出 `SHA256SUMS.minisig`。
  已有的檔案也可手動簽：`minisign -Sm SHA256SUMS -s ~/.minisign/cytrace.key`。
- **離線信任錨**：把上方公鑰字串與金鑰 ID **抄在交付驗收單上**（紙本即帶外管道），與交付媒體分開遞交；
  目標機驗收者以驗收單上的字串驗章，不使用交付媒體內附的任何公鑰。
- 目標機驗證：
  ```bash
  minisign -Vm SHA256SUMS -P <驗收單上的公鑰字串>   # 驗真實性
  sha256sum -c SHA256SUMS                            # 驗完整性
  ```

## 4. 目標機安裝與執行（無網路）

**Windows 目標機**（解開安裝包後，全部走 wrapper）：
```powershell
.\cytrace-offline.ps1 run dir:C:\path\to\target --fail-on high
```
wrapper 等效設定 `Path=<bundle>\bin`、`GRYPE_DB_CACHE_DIR=<bundle>\db`、
`GRYPE_DB_AUTO_UPDATE=false`、`GRYPE_DB_VALIDATE_AGE=false`（ADR-003）。

**Linux 目標機**：

```bash
# 解開安裝包後，全部走 wrapper（已內建離線設定）
./cytrace-offline run dir:/path/to/target --fail-on high
```
wrapper 等效於設定 `PATH=$BUNDLE/bin`、`GRYPE_DB_CACHE_DIR=$BUNDLE/db`、
`GRYPE_DB_AUTO_UPDATE=false`、`GRYPE_DB_VALIDATE_AGE=false`（ADR-003：舊快照不被年齡驗證中止）。

**常用選項**（兩平台相同）：
- `--cbom`：併同盤點密碼學資產（憑證、金鑰、演算法）；`--fail-on-quantum-vulnerable` 有量子脆弱資產即以 2 結束。
- 語言：`--lang en-US`，或設環境變數 `CYTRACE_LANG=en-US`；終端訊息、錯誤與 `--help` 皆依此語言。
  報表也以此語言開啟，可在報表內切換。
- 退出碼：`0` 正常；`2` 達門檻（`--fail-on` 或量子閘門）；`1` 錯誤（含參數打錯、引擎失敗，以及量子閘門
  未取得完整結果）。`1` 優先於 `2`。
- 用法：`cytrace --help`、`cytrace <子命令> --help`。

## 5. 漏洞 DB 離線更新（ADR-003）

1. **有網段**：`grype db update`（取最新庫）。
2. 重新 `make package`（或只打包 `~/.cache/grype/db` → 新 `db/` 快照）。
3. 以核可流程**攜入**目標機，替換 `cytrace-<版本>/db/`。
4. 報表會顯示 DB 快照版本/日期，使資料時效可稽核。

> 進場更新申請耗時 → DB 快照可獨立於 binary 更新（只換 `db/`），降低每次申請的變更面。

## 6. 平台注意（ADR-007 / ADR-010）

支援 x86_64 的 Linux（`x86_64-unknown-linux-musl`）與 Windows（`x86_64-pc-windows-msvc`）兩個平台，各有安裝包（§2）。
Windows 包的 CBOM 引擎已在 GitHub 的 Windows runner 上實際執行驗證，**尚未於場域 Windows 機器驗證**——
首次交付時請以含憑證的目錄跑一次 `--cbom` 確認。
arm64 或國產 Linux（麒麟、UOS、RHEL clone）**未支援**：須 cross-compile cytrace **與**重建對應平台的
syft／grype／theia，並重檢 musl 價值主張（musl 限 Linux）。

## 7. 容器交付（docker save/load；ADR-012）

容器是**新增交付形態**（跑 `cytrace serve` Web 服務），不取代裸機包。映像不含 grype DB
（slim + `/db` volume），故交付含兩件 artifact：**映像 tar** ＋ **DB 快照**（同 §5 那份）。

### 7.1 取得與封存（有網段交付工作站）
1. `docker pull ghcr.io/astroicers/cytrace:X.Y.Z`（需 GHCR 私有 read PAT）。
   > **tag push 路徑**的 image tag 無 `v` 前綴（semver pattern 去前綴；v0.2.1 實證
   > 為 `0.2.1`），照舊文件 pull `:vX.Y.Z` 會 404。**workflow_dispatch 補發例外**：
   > raw 規則原樣用輸入值——輸入 `v0.3.0` 就發 `:v0.3.0`，且不更新 `latest`；
   > 補發後請以實際 image tag 取代本節的 `X.Y.Z`。
2. 核對 digest：`docker buildx imagetools inspect ... --format '{{.Manifest.Digest}}'`
   對 GitHub Release 的 `IMAGE_DIGEST.txt`。
3. 取 Release 附的 `cytrace-vX.Y.Z-image.tar`（CI 產物即權威）或本機 `docker save`。
4. `sha256sum -c SHA256SUMS-image`（binaries 的校驗檔是另一份 `SHA256SUMS`——
   兩個 workflow 各附各的，檔名刻意錯開）。
5. **minisign 簽 tar**（交付工作站私鑰，同 §3 信任錨；私鑰不進 CI）：
   `minisign -Sm cytrace-vX.Y.Z-image.tar -s ~/.minisign/cytrace.key`。

### 7.2 攜入與載入（場域）
1. 光碟 / 單向匣攜入 → `minisign -Vm cytrace-vX.Y.Z-image.tar -P <驗收單上的公鑰字串>`（§3）＋ `sha256sum -c`。
2. `docker load -i cytrace-vX.Y.Z-image.tar`。
3. 補打 `latest` 標籤（離線 tar 只封 semver tag，而 DOCKER.md / docker-compose.yml
   範例用 `:latest`——不補打則照範例起站會 image not found）：
   `docker tag ghcr.io/astroicers/cytrace:X.Y.Z ghcr.io/astroicers/cytrace:latest`
4. 核對載入結果：`docker images --digests`。
   > 注意：`docker load` **不還原 RepoDigest**（registry digest）。核對的是 image ID /
   > config digest，與 §7.1 的 registry manifest digest 是不同概念——文件與驗收單須寫清楚。

### 7.3 啟動
依 DOCKER.md（run / compose 範例）。`/db` 掛入 §5 攜入的 DB 快照。
起站前以 `docker run --rm -it <image> hash-password` 產管理密碼 hash（需 `-it`：密碼由終端機讀取）。

### 7.4 DB 更新
**同 §5，只換 `/db` volume 內容並重啟容器；不需更新 image。**（slim 方案的紅利。）

### 7.5 映像更新
新版本走 7.1–7.3；舊映像保留一版作回滾窗口，確認新版無誤後 `docker rmi` 舊版。
