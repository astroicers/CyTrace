# [ADR-012]: 容器化交付與 GHCR image 維護

| 欄位 | 內容 |
|------|------|
| **狀態** | `Draft` |
| **接受日期** | — |
| **日期** | 2026-07-02 |
| **決策者** | CyTrace Team |

> **狀態說明：** `Draft`（初稿，禁止實作）→ `FIRM`（POC 驗證，允許 commit，需附驗證證據）→ `Accepted`（人類審核通過）

---

## 背景（Context）

ADR-011 引入 Web 服務模式（`cytrace serve`）。服務型部署最自然的交付形態是容器：
單一 image 內含 cytrace + 釘選 syft/grype，場域一鍵起站。使用者已確認：

1. **GHCR 私有** image、只建 **linux/amd64**；目標場域以 `docker save/load` 離線搬運
2. tag 策略：版本號 + latest

**定位**：容器是**新增交付形態**（服務模式），**不取代** ADR-007/010 的裸機離線包（CLI 模式）。
兩者共用：同一 musl binary 建置方式、同一釘選引擎版本、同一 grype DB 快照與更新 SOP、同一 minisign 信任錨。

**現況問題**：syft/grype 版本目前只釘在 `scripts/package.ps1`（1.45.1 / 0.114.0），package.sh 從 PATH
複製（人工保證版本）——引擎版本事實源分散，容器化會再加一處（Dockerfile），須收斂。

## 評估選項（Options Considered）

### grype DB 放置策略（核心決策）

#### 選項 A：DB 烤進 image
- **優點**：單一 artifact 自包含。
- **缺點**：image ~2GB；DB **月更**（ADR-003）而產品版本低頻——每月重 build/重 push/重 save/重搬 2GB，
  CI 時間、GHCR 私有儲存計費、光碟燒錄全被放大；DB 有問題 = 整顆 image 重發重驗；
  2GB 超過 GitHub Release 單檔上限，發佈通道也要另設計。

#### 選項 B：slim image + DB 以 `/db` volume 掛載（採用）
- **優點**：image ~60–90MB（可直接掛 GitHub Release）；DB 月更只換 volume 內容、image 不動，
  **直接沿用 DELIVERY_SOP 既有 DB 更新 SOP**；產品與 DB 解耦、各自簽章各自稽核；
  同一份 DB 快照同時餵裸機包與容器（單一事實源）。
- **缺點**：交付完整性依賴「image + DB 快照」兩件 artifact 配套 → 技術護欄：serve 啟動時驗 DB 目錄，
  缺失走 **degraded 啟動**（服務可起、掃描時明確報錯、`/healthz`/`/api/v1/version` 回報 DB 狀態）。

#### 選項 C：雙 tag（vX.Y.Z slim + vX.Y.Z-full 含 DB）
- **缺點**：兩套 build/驗證/文件，複雜度 ×2；保留為未來逃生門，現在不預付。

### image 簽章／驗證通道

- **cosign**：keyless 依賴 Fulcio/Rekor transparency log——**air-gapped 場域無法查驗**；
  registry 簽章在 `docker load` 側根本接觸不到。排除作為離線信任錨。
- **minisign 簽 `docker save` tar（採用）**：場域實際收到的 artifact 是 tar，
  與 ADR-007 現行信任錨完全同構——**同一把公鑰驗所有交付物**。
  私鑰不進 GitHub Secrets（軍規供應鏈不把長期信任錨放雲端 CI）；CI 產 tar + SHA256SUMS 掛 Release，
  minisign 簽章在交付工作站執行。

## 決策（Decision）

1. **Dockerfile 四階段**（repo 根目錄）：
   - S1 `frontend-builder`：`node:22-alpine@sha256:<digest>` + corepack pnpm 10 →
     `pnpm install --frozen-lockfile` → build 雙 entry（report 樣板 + console）。
     image 內**重建**前端並覆蓋 commit 產物——保證「image 內容 = 原始碼」。
   - S2 `rust-builder`：`rust:1.95.0-slim-bookworm@sha256:<digest>` + musl-tools（與 release.yml 同構建置路徑）→
     `cargo build --release --locked --target x86_64-unknown-linux-musl -p cytrace-cli`；BuildKit cache mount。
   - S3 `engines`：`ARG SYFT_VERSION/GRYPE_VERSION/…_SHA256`（預設值引自 `scripts/versions.env`）下載
     Anchore 官方 release tar.gz，**SHA256 比對不符即 build fail**（checksum 硬釘進 versions.env，可稽核）。
   - S4 runtime：**`gcr.io/distroless/static-debian12:nonroot@sha256:<digest>`**。
     理由：三個 binary 全靜態（cytrace musl、syft/grype Go static）；無 shell/套件管理器 →
     被 grype 回掃（dogfooding）近零 findings；內建 nonroot（65532）、tzdata、/tmp。
     否決 scratch（自造 passwd/tmp/tzdata 輪子）與 alpine（busybox/musl CVE 噪音 + shell 攻擊面）。
2. **烤死離線 env**：`GRYPE_DB_CACHE_DIR=/db`、`GRYPE_DB_AUTO_UPDATE=false`、`GRYPE_DB_VALIDATE_AGE=false`、
   **`SYFT_CHECK_FOR_APP_UPDATE=false`、`GRYPE_CHECK_FOR_APP_UPDATE=false`**（update-check 是現行裸機
   wrapper 未關的 outbound 洩漏點——本 ADR 一併回補 `cytrace-offline` wrapper 與 engine.rs）、
   `TZ=Asia/Taipei`、`HOME=/data`。`USER 65532:65532`、`ENTRYPOINT ["cytrace"]`、`CMD ["serve"]`
   （`docker run IMG --version` 天然可用）。
3. **Volumes / 執行安全基線**：`/data`（rw，job 與報表）、`/db`（ro）、`/scan-targets`（ro）、`/certs`（ro）、
   `/tmp` tmpfs（文件給 sizing 指引）；支援 `--read-only --cap-drop=ALL --security-opt no-new-privileges`；
   healthcheck 用新子命令 `cytrace health`（TCP connect 檢查 bind port——distroless 無 shell、避開 TLS 分歧、零新依賴）。
4. **DB 策略**：選項 **B**（slim + `/db` volume + degraded 啟動護欄）。
5. **GHCR workflow**（新檔 `.github/workflows/docker.yml`，獨立於 release.yml——權限最小化
   `packages: write` 各自宣告）：
   - PR（paths 過濾）：buildx build（不 push）+ 冒煙（`--version`；`serve` degraded 起站打 `/healthz`）
   - tag `v*` / workflow_dispatch：冒煙**通過才** push `ghcr.io/astroicers/cytrace:{X.Y.Z,latest}`
     （metadata-action 產 OCI labels）→ `docker save` tar + SHA256SUMS + image SBOM（syft 掃 image，
     buildx attestation 離線側看不到，故另落檔）→ 掛同版 GitHub Release + 記 `IMAGE_DIGEST.txt`
6. **簽章與離線搬運**：minisign 簽 docker save tar（交付工作站執行，私鑰不進 CI）；
   DELIVERY_SOP 新增 §7：pull/取 Release tar → 驗 sha256 + digest → 簽章 → 光碟/單向匣 →
   `minisign -Vm` + `sha256sum -c` → `docker load` → 核對 image ID（文件明載 registry digest ≠ load 後
   可見 digest 的差異）；DB 更新 = 只換 `/db` volume 內容 + 重啟，**不需更新 image**。
7. **引擎版本單一事實源**：新增 `scripts/versions.env`（SYFT/GRYPE 版本 + SHA256），
   package.sh / package.ps1 / Dockerfile ARG 預設 / CI 皆引用；bump 引擎版本只改一處。
8. **本機 Make targets**：`docker-build` / `docker-smoke` / `docker-save`（**不含 push**——
   `.claude/settings.json` deny 維持；push 只由 CI 執行）。

## 後果（Consequences）

**正面影響：**
- 服務模式一鍵起站；image 供應鏈全釘死（base digest、rust/node/pnpm 版本、引擎 SHA256、`--locked`、
  `--frozen-lockfile`）——可重現、可稽核；distroless + non-root + read-only rootfs，dogfooding 自掃趨近零 findings。

**負面影響 / 技術債：**
- **base image digest 需人工升版 SOP**（無 Renovate）：每次 release 前檢查 distroless/rust/node digest
  安全更新，bump 需重跑完整驗證。
- **GHCR 私有存取管理**：交付工作站需 fine-grained read-only PAT；發放/輪替/撤銷是新增管理面。
- **兩件 artifact 配套**（image + DB）：以 degraded 啟動 + health 回報 DB 狀態 + DELIVERY_SOP §7 收斂。
- 零外連在容器內靠 env + 無 client 依賴；**網路層隔離仍是場域責任**（文件明示 `--network` 建議）。
- buildx attestation（provenance/SBOM）只在 registry 端可驗；離線側以 Release 附的 SBOM 檔 + minisign 為準
  （兩套驗證通道適用場景寫進文件）。

**後續追蹤：**
- 引擎 update-check env 回補裸機 wrapper（package.sh/ps1）與 engine.rs。
- 若場域回饋強烈要求單一 artifact，屆時啟用選項 C（-full tag）。

## 成功指標（Success Metrics）

| 指標 | 目標值 | 驗證方式 | 檢查時間 |
|------|--------|----------|----------|
| image 大小（slim） | < 150MB | CI 記錄 | 每次 build |
| 冒煙通過才 push | 壞 image 不進 GHCR | docker.yml 步驟順序 | 每次 tag |
| 可重現輸入全釘死 | base digest / 引擎 SHA256 / --locked | Dockerfile + versions.env 審查 | 每次 release |
| 離線可驗 | tar 的 SHA256SUMS + minisign 通過；load 後 image ID 相符 | DELIVERY_SOP §7 演練 | 首次交付 |
| dogfooding 回掃 | image 經 grype 掃描，findings 檢視並記錄 | CI report-only 步驟 | 每次 tag |
| DB 缺失防呆 | 無 `/db` 時 serve 可起、`/healthz` 回報 db absent、掃描報 503 | CI 冒煙 | 每次 push |

## 關聯（Relations）

- 前提：ADR-011（Web 服務模式——容器主要跑 `cytrace serve`）
- 沿用：ADR-003（grype DB 離線快照與更新 SOP）、ADR-007（minisign 信任錨；裸機包路線不變）、
  ADR-010（release.yml 職責不變；docker.yml 獨立）
- 修訂：DELIVERY_SOP（新增 §7 容器交付）；scripts/package.{sh,ps1}（引用 versions.env + 補 update-check env）
- 參考：ROADMAP M8（T808）
