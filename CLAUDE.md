# CyTrace — AI 行為設定

> ASP v5 | 讀取順序：本檔案 → `.asp-compiled-profile.md`（asp-compile 編譯產物，檔頭列來源清單；
> 不存在時依 `.ai_profile` 載入散文 profile 為 fallback）→ `~/.claude/CLAUDE.md`（user-level 鐵則）
> Profile 邏輯與 ASP skills 詳見 `~/.claude/asp/profiles/` 與 `~/.claude/skills/asp/`

<!-- ASP-AUTO-PROJECT-DESCRIPTION:START -->
## 專案說明

**CyTrace** 是**地端、無網際網路（軍用網路）場域的軟體依賴風險報表產生器**。
封裝 **Syft**（產 SBOM）與 **Grype**（比對 CVE）兩個 Apache-2.0 工具，一鍵產出可併入交件的
**依賴風險報表**與**軟體產品文件表（SBOM）**。原設計文件暫名 `twsbom`，正式產品名為 **CyTrace**。

- **核心語言**：Rust（單一 musl 靜態 binary、零 runtime 依賴、可簽章/checksum 稽核）
- **前端**：visual-web-stack DOM/UI 子集（React 19 + Vite + Tailwind + Radix UI + Motion + next-themes + Zustand + react-i18next）；**不含** 3D/R3F/滾動敘事
- **入口**：`cytrace` CLI（子命令 `run` / `scan` / `report`）
- **報表**：自包含**離線單檔 HTML**，由 Rust 核心 `rust-embed` 內嵌前端 bundle、產生時注入掃描資料
- **交付**：靜態 binary ＋ 釘選版 Syft/Grype ＋ grype DB 離線快照（單包）
- **架構文件**：`docs/SRS.md`、`docs/SDS.md`、`docs/UIUX_SPEC.md`
- **ADR**：`docs/adr/ADR-001 ～ ADR-010`（狀態見各檔檔頭）
- **ROADMAP**：`ROADMAP.yaml` 為**唯一 live 狀態權威**；autopilot 依此逐任務執行
<!-- ASP-AUTO-PROJECT-DESCRIPTION:END -->

## 特殊鐵則（覆蓋 / 補強 user-level 預設）

| 鐵則 | 說明 |
|------|------|
| **零外連（air-gapped）** | 產品執行期、報表、CI 一律不得有任何網路請求。報表 HTML 以 CSP 鎖死外連；前端字型本地子集化 woff2（`provider: none`）。所有依賴 vendored、lockfile 釘死。 |
| **穩定優先於功能** | 釘選 Rust toolchain、所有 crate、Syft/Grype 版本與 grype DB 快照。升級引擎才動 golden baseline。可重現建置（reproducible build）。不引入非必要複雜功能。 |
| **i18n 雙語強制** | 只支援 `zh-TW`（fallback）與 `en-US`。前端走 `react-i18next`、CLI 輸出走相同 locale 鍵；**禁止硬編碼任何使用者可見字串**（`frontend_quality` profile 把關）。 |
| **供應鏈純淨** | 交件僅含 Syft/Grype（Apache-2.0），NOTICE 標示來源。**明確禁止引入中國來源依賴（如 OpenSCA-cli）**。CyTrace 自身 dogfooding 產 SBOM 隨附。 |
| **信任邊界（不外傳）** | 掃描目標與原始碼**絕不離開目標機**（地端版不上傳任何資料）；支援含機密等級目標。SaaS 只收 SBOM 且延後（範圍外）。（NFR-09） |
| **ADR 未定案禁止實作** | `Draft` ADR 禁止寫對應生產代碼（user-level 鐵則）。本專案 7 份 ADR 初始為 Draft，須人類 `/asp:approve-adr` 升 `Accepted` 後 autopilot 才解鎖該里程碑。 |
| **破壞性操作防護** | `git push origin main / --force / rebase / rm -rf / docker push / gh pr merge` 必須人類確認（沿用 user-level 鐵則與 `.claude/settings.json` deny 清單）。 |

## 範圍邊界

- **不做**：SaaS 雲端監管（ROADMAP M6 延後、不進 autopilot 佇列）、PDF 報表（先單檔 HTML，ADR-005 註記延後）、3D/滾動視覺敘事。
- **語言/工具鏈**：Rust 核心 + Node（前端 build）。兩者皆需離線可建。
- **Bootstrap commit 註記**：本治理骨架早於測試骨架（`make test` 於 M0/T002 才建立），首次純文件 commit 會被 PreToolUse ship-gate 擋（無 `.asp-test-result.json`）；以 `ASP_SHIP_OK=1 git commit ...` 放行（會留 telemetry）。M0 之後正常測試流程即可。
