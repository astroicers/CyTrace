# CyTrace — 專案 Makefile
#
# ASP 指令（autopilot-* / adr-new / spec-new / audit-health / asp-gate …）來自
# user-level 安裝的 ~/.claude/asp/Makefile.inc（v5 共用層）。
# 下方 build/test/lint/coverage 刻意覆寫 Makefile.inc 的 Docker/Go 通用版為 Cargo 版
# （Make 會印 "overriding recipe" 警告，屬預期、無害）。

-include $(HOME)/.claude/asp/Makefile.inc

.PHONY: info build test test-real-engine lint clippy fmt fmt-check coverage clean-rs frontend frontend-check frontend-console package docker-build docker-smoke docker-save

info:
	@echo "CyTrace — 地端依賴風險報表產生器（Rust workspace + 報表前端）"
	@echo "ASP 指令見 'make help'；產品指令：frontend / build / test / lint / coverage"

# ── 前端報表（M3）：build 單檔 → 複製成 cytrace-report 內嵌資產 ──
# 注意：crates/cytrace-report/assets/report-template.html 為產物但已 commit，
# 使 cargo build 免前端步驟即可（include_str!）。改前端後跑 make frontend 重產。
frontend:
	cd frontend && pnpm install --frozen-lockfile && pnpm build
	cp frontend/dist/index.html crates/cytrace-report/assets/report-template.html
	@echo "✓ 報表樣板已更新（assets/report-template.html）"

frontend-check:
	cd frontend && pnpm typecheck
	@# frontend/src/cbom.ts 是 Catalog::render_cbom 的第二份實作；Rust 側的契約測試比對
	@# 鍵清單與變數名規則，擋不到行為差異（實際漂開過兩次：空細節漏佔位符、en-US 夾全角）
	node --experimental-strip-types frontend/scripts/cbom-message-check.mts
	node --experimental-strip-types frontend/scripts/console-lang-check.mts
	node --experimental-strip-types frontend/scripts/ui-literal-check.mts
	node --experimental-strip-types frontend/scripts/report-lang-check.mts

# Console SPA（ADR-011）：產物 commit 至 crates/cytrace-server/assets/console/（rust-embed）。
# 改 console 前端後跑 make frontend-console 重產。
frontend-console:
	cd frontend && pnpm install --frozen-lockfile && pnpm build:console
	rm -rf crates/cytrace-server/assets/console
	mkdir -p crates/cytrace-server/assets/console
	cp -r frontend/dist-console/. crates/cytrace-server/assets/console/
	@echo "✓ console 已更新（crates/cytrace-server/assets/console/）"

# ── 產品（Rust workspace）──
build:
	cargo build --workspace

test:
	cargo test --workspace

# 真引擎 × 真實輸入形態的整合測試（ADR-013）。
# 需要 cbomkit-theia 在 PATH；air-gapped CI 無引擎時這些案例為 #[ignore]，
# 故 `make test` 不會跑到，須顯式呼叫本 target。
#
# 存在理由：M9 六輪複審中，第四輪之後的全部阻斷級都是「真引擎在常見輸入上的實際行為」
# （零資產目標輸出 null、dir 模式追隨 symlink、FIFO 掛死、OpenSSH 金鑰只在 stderr 留痕、
# 憑證計數走 numberOfDetectedCertificates 而非我們以為的 Found N certificate(s)），
# 用 fixture 與 fake engine 一個都測不到——連我們自己寫的 fixture 都在說謊。
test-real-engine:
	@command -v cbomkit-theia >/dev/null || { echo "✗ 找不到 cbomkit-theia；先跑 scripts/build-theia.sh"; exit 1; }
	@# 案例缺工具時會 panic（本層不接受靜默略過），故前置一併檢查以給出清楚訊息
	@for t in openssl ssh-keygen mkfifo; do 		command -v $$t >/dev/null || { echo "✗ 找不到 $$t（真引擎案例需要）"; exit 1; }; 	done
	cargo test -p cytrace-core --test real_engine -- --ignored

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all --check

clippy:
	cargo clippy --workspace --all-targets -- -D warnings

# ASP standard 閘的 lint＝格式 + clippy（NFR：穩定、零 warning）。
# 需有 recipe 才能覆寫 Makefile.inc 的通用 lint（否則只是追加前置相依）。
lint: fmt-check clippy
	python3 scripts/i18n-check.py
	python3 scripts/notice-parity-check.py
	@# 對抽取邏輯注入故障，確認結構性檢查（區段數 / OUTSIDE needle / 空值）真的會紅
	@# ——初版與二版都是「逐列變異」，兩版的判別力都等於正常執行（第八輪複審 finding C）
	python3 scripts/notice-parity-check.py --verify-sentinels
	@# Release 說明只有 release.yml 能寫、內容取自 CHANGELOG（v0.3.0 的說明被 docker.yml 整份覆蓋過）
	python3 scripts/release-notes.py check
	@# 報表成因渲染：本組織 GitHub 為 free 方案、CI 無法設為 required（user-level 實查），
	@# 故「只在 CI 跑」實質等於「只在事後偵測」；land 前的閘必須跑到（第八輪複審 finding K）。
	@# 只呼叫這一支而非整個 frontend-check：pnpm 在部分環境會先做 deps check 並要求
	@# 互動核准 build script（esbuild），會讓整條 lint 壞掉；typecheck 仍由 CI 與
	@# make frontend-check 承接。
	@# 前置缺席時給明確訊息並**仍然失敗**（fail-closed）——直接讓 node 報 MODULE_NOT_FOUND
	@# 會被當成環境雜訊而被忽略，那等於這道檢查在該機器上靜默消失（第九輪複審）。
	@command -v node >/dev/null || { echo "✗ 找不到 node（CBOM 成因渲染檢查需 Node ≥ 22 的型別剝離）"; exit 1; }
	@node -e 'const [maj]=process.versions.node.split(".").map(Number); if (maj < 22) { console.error("✗ Node " + process.versions.node + " 過舊：--experimental-strip-types 需 22+"); process.exit(1) }'
	@test -d frontend/node_modules/i18next || { echo "✗ 缺 frontend/node_modules/i18next（先跑 make frontend 或 npm --prefix frontend install）"; exit 1; }
	node --experimental-strip-types frontend/scripts/cbom-message-check.mts
	@# console 實際送出的語系必須等於畫面語系（T909；第二輪複審 lang#0 / tests#0）；與上一支同一套前置
	node --experimental-strip-types frontend/scripts/console-lang-check.mts
	@# 畫面不得硬編碼使用者可見字串（T917）；需 typescript 剖析 AST，前置缺席同樣 fail-closed
	@test -d frontend/node_modules/typescript || { echo "✗ 缺 frontend/node_modules/typescript（先跑 make frontend 或 npm --prefix frontend install）"; exit 1; }
	node --experimental-strip-types frontend/scripts/ui-literal-check.mts
	@# 報表以產生時的語言開啟（T918）；載入真的 src/i18n.ts，與上兩支同一套前置
	node --experimental-strip-types frontend/scripts/report-lang-check.mts
	@echo "✓ lint passed（fmt + clippy + i18n + NOTICE 對帳與哨兵 + CBOM 成因渲染 + console 語系 + 前端字面值 + 報表開啟語言，零 warning）"

# 覆蓋率：有 cargo-llvm-cov 用之，否則退回跑測試（NFR-07 目標 ≥ 80%）
coverage:
	@if command -v cargo-llvm-cov >/dev/null 2>&1; then \
		cargo llvm-cov --workspace --summary-only; \
	else \
		echo "⚠️  cargo-llvm-cov 未安裝（離線封裝時加入）；改跑測試確保綠燈"; \
		cargo test --workspace; \
	fi

clean-rs:
	cargo clean

# ── M4 離線安裝包（ADR-007 / DELIVERY_SOP）──
package:
	bash scripts/package.sh

# ── M8 容器（ADR-012）；本機驗證用，不含 push（push 只由 CI docker.yml 執行）──
DOCKER_IMAGE ?= ghcr.io/astroicers/cytrace:dev
docker-build:
	. scripts/versions.env && docker build \
	  --build-arg SYFT_VERSION=$$SYFT_VERSION \
	  --build-arg GRYPE_VERSION=$$GRYPE_VERSION \
	  --build-arg SYFT_LINUX_AMD64_SHA256=$$SYFT_LINUX_AMD64_SHA256 \
	  --build-arg GRYPE_LINUX_AMD64_SHA256=$$GRYPE_LINUX_AMD64_SHA256 \
	  -t $(DOCKER_IMAGE) .

docker-smoke:
	docker run --rm $(DOCKER_IMAGE) --version

docker-save:
	docker save $(DOCKER_IMAGE) -o cytrace-image.tar
	sha256sum cytrace-image.tar > SHA256SUMS
	@echo "✓ cytrace-image.tar + SHA256SUMS（交付工作站以 minisign 簽章，見 DELIVERY_SOP §7）"
