# [ADR-007]: 交付與封裝（離線安裝包、不隨裝軟體標）

| 欄位 | 內容 |
|------|------|
| **狀態** | `Draft` |
| **日期** | 2026-06-24 |
| **決策者** | CyTrace Team |

> **狀態說明：** `Draft`（初稿，禁止實作）→ `FIRM`（POC 驗證，允許 commit，需附驗證證據）→ `Accepted`（人類審核通過）

---

## 背景（Context）

CyTrace 交付到**軍用地端**，進場部署/更新申請耗時，**穩定與可稽核**是第一優先。交付物需要：
可離線安裝、版本可釘選、可簽章/checksum 驗證、且**自身供應鏈乾淨**（dogfooding 產 SBOM）。
原設計文件特別強調走「**封裝軟體棒（隨身碟離線安裝包）**」路線、**不走第三方資安檢測（隨裝軟體標）**。

## 評估選項（Options Considered）

### 選項 A：單包離線安裝（musl 靜態 binary + 釘選引擎 + grype DB 快照 + 簽章）
- **優點**：一次攜入即可離線運作；版本全部釘選、可重現；binary 與引擎可 `sha256` + 簽章驗證；附 CyTrace 自產 SBOM。符合「不隨裝軟體標、走離線安裝包」路線。
- **缺點**：安裝包體積較大（含引擎與 DB 快照）。
- **風險**：引擎/DB 更新需重新打包攜入（已由 ADR-003 SOP 涵蓋）。

### 選項 B：依賴目標機既有環境/連線安裝
- **優點**：包小。
- **缺點**：違反 air-gapped 與穩定前提，不可行。

## 決策（Decision）

採用 **選項 A**：交付物＝**單一離線安裝包**，內含
（1）`cytrace` musl 靜態 binary、
（2）**釘選版** Syft / Grype binary、
（3）**grype DB 離線快照**、
（4）`SHA256SUMS` 與簽章、
（5）CyTrace **自產 SBOM（dogfooding）** 與 NOTICE（第三方授權）。
**走離線安裝包路線、不走第三方資安檢測（隨裝軟體標）。** 所有版本釘選、可重現建置。

**目標平台（triple）決策：**
- 預設目標 = `x86_64-unknown-linux-musl`；musl 靜態優於 glibc 靜態（避免 glibc 部分靜態連結陷阱，零 runtime，理由見 ADR-001）。
- ⚠️ 此為**未驗證假設**：軍用地端可能是 Windows / arm64 / 國產 Linux（麒麟、UOS、RHEL clone）。**M4（T401）前須向驗收單位確認 OS/架構**；
  非 x86_64-linux 須同時 cross-compile Rust binary **與**重建隨附的 Syft/Grype Go binary（各有自己的 triple），並重檢 musl 價值主張（musl 限 Linux）。
- arm64/aarch64 是否納入驗收環境：本 ADR 預設**範圍外**，待驗收確認再開。

**簽章與離線信任錨（NEW-3）：**
- **明選簽章工具/格式**：`minisign`（或 cosign 之 detached signature），對 binary 與安裝包產生 detached 簽章；摘要演算法 SHA-256。
- `SHA256SUMS` 只提供**完整性**（攻擊者可同時改 binary 與 SHA 檔），真實性靠**簽章**。
- **離線信任錨**：簽章公鑰須以**帶外（out-of-band）方式預先匯入**斷網目標機並建立信任；金鑰保管/輪替流程於交付 SOP 定義。

## 後果（Consequences）

**正面影響：**
- 離線一包到位、可簽章稽核、供應鏈透明；符合軍用採購偏好。

**負面影響 / 技術債：**
- 安裝包體積大；引擎/DB 更新需重新打包（走 ADR-003 SOP）。

**後續追蹤：**
- golden baseline 回歸測試策略由 **ADR-008** 擁有（ROADMAP T503），確保釘選引擎升級不破壞輸出。
- 簽章工具/格式已定（minisign / cosign detached，見決策）；金鑰保管與輪替流程於交付 SOP 細化。
- 目標平台須於 M4 前向驗收單位確認（見決策）。

## 成功指標（Success Metrics）

| 指標 | 目標值 | 驗證方式 | 檢查時間 |
|------|--------|----------|----------|
| 安裝包可離線安裝並執行 | 是 | 斷網機器依包安裝後 `cytrace run` 成功 | M4 |
| 交付物可驗證真實性 | 是 | 在斷網機器以**預先帶外匯入的公鑰**驗 detached 簽章通過（非只 `sha256sum -c`） | M4 |
| 隨附自產 SBOM | 是 | 安裝包含 CyTrace SBOM 檔 | M4 |
| 可重現建置 | 位元級一致（盡力） | 兩次乾淨環境 build 比對 | M5 |

## 關聯（Relations）

- 參考：ADR-001（binary）、ADR-002（引擎）、ADR-003（DB 快照/更新）、ROADMAP M4/M5
