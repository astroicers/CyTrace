# [ADR-010]: 雙平台發布（Windows + Linux）與 GitHub Release 流水線

| 欄位 | 內容 |
|------|------|
| **狀態** | `Accepted` |
| **接受日期** | 2026-06-24（使用者要求雙平台發布，授權代為升版） |
| **日期** | 2026-06-24 |
| **決策者** | CyTrace Team |

> **狀態說明：** `Draft`（初稿，禁止實作）→ `FIRM`（POC 驗證，允許 commit，需附驗證證據）→ `Accepted`（人類審核通過）

---

## 背景（Context）

ADR-007 將目標平台**假設**為 `x86_64-unknown-linux-musl`，並明確標註「**目標平台須於 M4 前向驗收單位確認**」。
使用者已確認：**軍方電腦以 Windows 為多數**。因此原 Linux 假設不符實際驗收環境，**Windows 須列為主要目標**，
且仍需保留 Linux 給 Linux 機房。需要一條自動化流水線，從同一份原始碼**同時 build 並發布 Windows 與 Linux 兩個版本**。

> 前置事實已驗證：`cargo check --target x86_64-pc-windows-gnu --workspace` 全數通過——程式碼零修改即可為 Windows 編譯（無 unix-only 寫法）。

## 評估選項（Options Considered）

### 選項 A：雙平台（Windows `x86_64-pc-windows-msvc` 靜態 CRT + Linux `x86_64-unknown-linux-musl` 靜態），GitHub Actions matrix 發布
- **優點**：涵蓋軍方主流（Windows）與 Linux 機房；兩者皆**單一執行檔、零 runtime 依賴**（msvc 靜態 CRT 免 VC++ redist、musl 免 glibc）；同源 build、可重現。
- **缺點**：兩條 build 矩陣；Windows 端的 syft/grype 也要釘選對應版本。
- **風險**：Windows 路徑/權限差異 → 已驗證程式碼可攜，且 CI 在真實 windows-latest 上 build+test。

### 選項 B：只發 Windows
- **缺點**：放棄 Linux 機房，縮小適用面。

### 選項 C：維持只 Linux（ADR-007 原案）
- **缺點**：不符軍方主流環境，等同不可交付。

## 決策（Decision）

採用 **選項 A**。

1. **目標平台（triple）**：
   - Windows（主）：`x86_64-pc-windows-msvc`，`-C target-feature=+crt-static`（靜態 CRT → 單一 `cytrace.exe`、免 VC++ 可轉散發套件）。
   - Linux：`x86_64-unknown-linux-musl`（靜態，沿用 ADR-001/007）。
2. **發布流水線**：GitHub Actions **matrix**（`windows-latest` / `ubuntu-latest`）→ 各自 `cargo build --release` →
   蒐集 `cytrace.exe` 與 `cytrace` → 產 `SHA256SUMS` → 建立 **GitHub Release** 並上傳兩個 binary。
   觸發：push tag `v*`（並支援手動 `workflow_dispatch`）。
3. **GitHub Release 範圍**：只發**執行檔 + SHA256SUMS**（輕量、公開可下載）。**完整 air-gapped 安裝包**
   （含釘選引擎 + grype DB 快照，~GB 級）仍由 `make package` 於交付端**逐平台**產生，不放進 GitHub Release。
4. **隨平台引擎**：air-gapped 安裝包帶**對應 OS 的** syft/grype（Windows 帶 `syft.exe`/`grype.exe`）；**grype DB 快照跨平台通用**。
5. **簽章**：沿用 ADR-007（minisign detached + 帶外信任錨），對兩平台安裝包同等適用。

## 後果（Consequences）

**正面影響：**
- 一條流水線同時產 Windows + Linux 單檔零依賴執行檔，符合軍方主流與 Linux 機房。
- 真實 Windows runner build+test，平台相容性持續被 CI 守住。

**負面影響 / 技術債：**
- 維護雙 build 矩陣；Windows 端引擎需另行釘選/簽章（交付端封裝）。
- ADR-007 的「平台未定」開放項由本 ADR 收斂（ADR-007 加交叉註記）。

**後續追蹤：**
- 交付端 `make package` 需 Windows 變體（`.ps1` 安裝包 + `.bat`/`.ps1` wrapper + `syft.exe`/`grype.exe`）。本 ADR 先落地 GitHub Release 的執行檔；Windows 完整安裝包封裝列為後續任務。

## 成功指標（Success Metrics）

| 指標 | 目標值 | 驗證方式 | 檢查時間 |
|------|--------|----------|----------|
| Release 含雙平台執行檔 | `cytrace`(linux) + `cytrace.exe`(windows) | GitHub Release assets | 首次 release |
| Windows 冷機可跑 | 是 | 乾淨 Windows（無 VC++ redist）執行 `cytrace.exe --version` / `report` | 首次 release |
| 完整性可驗 | 是 | `sha256sum -c SHA256SUMS` | 每次 release |
| CI 在真實 Windows build+test 綠 | 是 | Actions windows-latest job | 每次 push |

## 關聯（Relations）

- 擴充 / 收斂：ADR-007（封裝與平台；本 ADR 確定平台為 Windows 主 + Linux）
- 參考：ADR-001（靜態 binary）、ADR-003（grype DB 跨平台快照）、ROADMAP M7
