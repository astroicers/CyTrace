# CyTrace 離線交付與更新 SOP

> 對應 ADR-003（離線漏洞 DB）、ADR-007（封裝/簽章/信任錨）。場域：軍用地端、無網際網路。

## 1. 安裝包內容（單一可攜目錄）

```
cytrace-<版本>/
├── bin/
│   ├── cytrace            # musl 靜態 binary（零 runtime 依賴）
│   ├── syft               # 釘選版（產 SBOM）
│   └── grype              # 釘選版（比對 CVE）
├── db/                    # grype 漏洞 DB 離線快照（含建立日期）
├── cytrace.sbom.cdx.json  # CyTrace 自產 SBOM（dogfooding，FR-009）
├── NOTICE                 # 第三方授權（Syft/Grype 等，皆 Apache-2.0）
├── cytrace-offline        # 離線執行 wrapper（設定 PATH 與 GRYPE_DB_CACHE_DIR）
├── SHA256SUMS             # 完整性
└── SHA256SUMS.minisig     # 真實性（minisign detached 簽章）
```

## 2. 產生安裝包（有網段 / build 機）

```bash
make package            # 或 scripts/package.sh <輸出目錄>
```
腳本會：build musl 靜態 binary → 收集釘選引擎與 grype DB 快照 → 產自產 SBOM →
寫 NOTICE → 算 SHA256SUMS →（若有金鑰）minisign 簽章。

## 3. 簽章與離線信任錨（ADR-007 / NEW-3）

- 簽章工具：**minisign**（detached，SHA-256）。
- build 機產生金鑰一次：`minisign -G`（妥善保管私鑰；公鑰隨交付流程帶外發布）。
- 簽章：`minisign -Sm SHA256SUMS`（產 `SHA256SUMS.minisig`）。
- **離線信任錨**：目標機驗收前，**以帶外方式**（紙本/光碟/獨立通道）預先匯入 `minisign` 公鑰並建立信任。
- 目標機驗證：
  ```bash
  minisign -Vm SHA256SUMS -P <已帶外匯入的公鑰>   # 驗真實性
  sha256sum -c SHA256SUMS                          # 驗完整性
  ```

## 4. 目標機安裝與執行（無網路）

```bash
# 解開安裝包後，全部走 wrapper（已內建離線設定）
./cytrace-offline run dir:/path/to/target --fail-on high
```
wrapper 等效於設定 `PATH=$BUNDLE/bin`、`GRYPE_DB_CACHE_DIR=$BUNDLE/db`、
`GRYPE_DB_AUTO_UPDATE=false`、`GRYPE_DB_VALIDATE_AGE=false`（ADR-003：舊快照不被年齡驗證中止）。

## 5. 漏洞 DB 離線更新（ADR-003）

1. **有網段**：`grype db update`（取最新庫）。
2. 重新 `make package`（或只打包 `~/.cache/grype/db` → 新 `db/` 快照）。
3. 以核可流程**攜入**目標機，替換 `cytrace-<版本>/db/`。
4. 報表會顯示 DB 快照版本/日期，使資料時效可稽核。

> 進場更新申請耗時 → DB 快照可獨立於 binary 更新（只換 `db/`），降低每次申請的變更面。

## 6. 平台注意（ADR-007）

預設目標 = `x86_64-unknown-linux-musl`。若驗收環境為 Windows / arm64 / 國產 Linux，
須 cross-compile cytrace **與**重建對應平台的 syft/grype，並重檢 musl 價值主張（musl 限 Linux）。
