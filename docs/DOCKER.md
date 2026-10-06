# CyTrace 容器部署（ADR-012）

> **air-gapped 場域注意**：本檔範例用 `:latest`。離線 tar 只封 semver tag
>（如 `0.5.0`），`docker load` 後須先補打：
> `docker tag ghcr.io/astroicers/cytrace:X.Y.Z ghcr.io/astroicers/cytrace:latest`
>（見 DELIVERY_SOP §7.2）。

CyTrace 容器跑 `cytrace serve` Web 服務模式（登入控制台 + 掃描/報表 API）。
容器是**新增交付形態**，不取代 ADR-007 的裸機離線包。

- **映像**：`ghcr.io/astroicers/cytrace`（GHCR 私有，linux/amd64）
- **base**：distroless static（non-root 65532、無 shell、read-only rootfs 可行）
- **引擎**：Syft、Grype、CBOMkit-theia 皆已在映像內（釘選版本，見 `scripts/versions.env`）；控制台的
  「CBOM」勾選項可直接使用
- **grype DB**：**不烤進 image**（slim，選項 B）；以 `/db` volume 掛入（DB 月更只換 volume）

## 快速上手

```bash
# 1) 產生管理密碼 hash（不收明文）
docker run --rm -it ghcr.io/astroicers/cytrace:latest hash-password
# 輸出 $argon2id$... 字串

# 2) 起站（最小；HTTP 明文，內網測試用）
docker run -d --name cytrace --read-only \
  --cap-drop=ALL --security-opt no-new-privileges \
  --tmpfs /tmp:size=1g \
  -p 8443:8443 \
  -v /srv/cytrace/data:/data \
  -v /srv/cytrace/db:/db:ro \
  -e CYTRACE_ADMIN_PASSWORD_HASH='<上一步的 hash>' \
  ghcr.io/astroicers/cytrace:latest

# 3) 瀏覽器開 http://<host>:8443 登入
```

或用 `docker-compose.yml`（repo 根，生產範例）：
```bash
export CYTRACE_ADMIN_PASSWORD_HASH='<hash>'
docker compose up -d
```

## Volumes

| 掛載點 | 模式 | 用途 |
|--------|------|------|
| `/data` | rw | job 結果、報表、上傳暫存（映像內已 chown 65532，空 volume 繼承） |
| `/db` | ro | grype DB 快照（同 DELIVERY_SOP §5 更新的那一份） |
| `/scan-targets` | ro | 掛載目錄掃描目標（搭配 `CYTRACE_SCAN_ROOTS`） |
| `/certs` | ro | TLS 憑證 `tls.crt` / `tls.key`（選用） |

## 環境變數

| 變數 | 預設 | 說明 |
|------|------|------|
| `CYTRACE_ADMIN_PASSWORD_HASH` | （必填） | argon2id PHC；缺失或格式錯 → 拒絕啟動 |
| `CYTRACE_ADMIN_USER` | `admin` | 管理帳號的顯示名稱 |
| `CYTRACE_BIND` | `0.0.0.0:8443` | 監聽位址 |
| `CYTRACE_TLS_CERT` / `CYTRACE_TLS_KEY` | 未設 | 成對設定啟用 HTTPS（未設 = HTTP 明文，啟動印警告） |
| `CYTRACE_SCAN_ROOTS` | 未設 | `name=/abs/path,...` 掛載掃描白名單 |
| `CYTRACE_SESSION_TTL_HOURS` | 12 | session 絕對過期 |
| `CYTRACE_MAX_UPLOAD_MB` | 512 | 上傳大小上限 |
| `CYTRACE_MAX_EXTRACT_MB` | min(上傳上限×10, 4096) | 上傳封存檔解壓後的總量上限 |
| `CYTRACE_MAX_CONCURRENT_SCANS` | 2 | 同時掃描上限 |
| `CYTRACE_MAX_QUEUED` | 32 | 佇列上限（排隊中與執行中的任務總數；滿了回 429） |
| `CYTRACE_DATA_DIR` | `/data` | 資料目錄（容器內通常不改，改掛 volume） |
| `CYTRACE_KEEP_INPUT` | false | 是否保留上傳原檔。為 false 時，掃描結束、排隊中被取消、伺服器重啟這三個時機都會刪除 |
| `CYTRACE_LANG` | `zh-TW` | 容器日誌（啟動錯誤、job 隔離與落盤警告）的語言：`zh-TW`／`en-US`。**不影響** console 與 API 的語言（依瀏覽器各自協商） |

離線鐵則（`GRYPE_DB_CACHE_DIR=/db`、`GRYPE_DB_AUTO_UPDATE=false`、`GRYPE_DB_VALIDATE_AGE=false`、
`SYFT/GRYPE_CHECK_FOR_APP_UPDATE=false` 等）已烤進映像，無需設定。

上表變數的值必須是合法的 UTF-8，否則啟動時以退出碼 1 結束並指名該變數；已由命令列旗標覆寫的變數不受影響。
數值類變數不是整數時同樣拒絕啟動，訊息會指出是哪個變數。

## 啟用 TLS

```bash
docker run -d --name cytrace --read-only \
  --cap-drop=ALL --security-opt no-new-privileges --tmpfs /tmp:size=1g \
  -p 8443:8443 \
  -v /srv/cytrace/data:/data -v /srv/cytrace/db:/db:ro \
  -v /srv/cytrace/certs:/certs:ro \
  -e CYTRACE_ADMIN_PASSWORD_HASH='<hash>' \
  -e CYTRACE_TLS_CERT=/certs/tls.crt -e CYTRACE_TLS_KEY=/certs/tls.key \
  ghcr.io/astroicers/cytrace:latest
```
軍規場域通常有自建 PKI；掛入場域簽發的憑證即可（不做 ACME/自簽）。

## Healthcheck

映像無 shell，healthcheck 用內建 `cytrace health`（TCP connect 檢查 bind port）：
```yaml
healthcheck:
  test: ["CMD", "cytrace", "health"]
```

## 停止（`docker stop`）

`docker stop` 送 SIGTERM：服務停止接受新連線，給進行中的請求最多 10 秒完成，之後以退出碼 0 結束。
執行中的掃描不會等它跑完；它在 `/data` 的記錄於下次啟動時標為 `interrupted`，可再送一次。

## 安全基線

- non-root（UID/GID 65532）；建議 `--read-only`（唯二可寫：`/data` volume 與 `/tmp` tmpfs）
- `--cap-drop=ALL --security-opt no-new-privileges`
- **網路層隔離仍是場域責任**：零外連靠 env 旗標 + 無 HTTP client 依賴，
  建議另以 `--network` 限制 outbound（第二道防線）
- `/tmp` tmpfs sizing：大型掃描目標經 syft 暫存可能超過預設；`ENOSPC` 時調大 `size=`

## DB 缺失（degraded）

未掛 `/db` 或 DB 為空時，服務**可正常起站**（登入/瀏覽可用），
但掃描回 `503 db_missing`；`/api/v1/version` 的 `db.present` 回報 `false`。
用途：CI 冒煙免搬 1.7GB DB、場域 fail-fast 診斷。

## 離線搬運

見 [DELIVERY_SOP.md](DELIVERY_SOP.md) §7（`docker save` → 驗 → minisign 簽 → 光碟 → `docker load`）。
