# CyTrace — 專案 Makefile
#
# ASP 指令（autopilot-* / adr-new / spec-new / audit-health / asp-gate …）來自
# user-level 安裝的 ~/.claude/asp/Makefile.inc（v5 共用層）。
# 下方 build/test/lint/coverage 刻意覆寫 Makefile.inc 的 Docker/Go 通用版為 Cargo 版
# （Make 會印 "overriding recipe" 警告，屬預期、無害）。

-include $(HOME)/.claude/asp/Makefile.inc

.PHONY: info build test lint clippy fmt fmt-check coverage clean-rs frontend frontend-check

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

# ── 產品（Rust workspace）──
build:
	cargo build --workspace

test:
	cargo test --workspace

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all --check

clippy:
	cargo clippy --workspace --all-targets -- -D warnings

# ASP standard 閘的 lint＝格式 + clippy（NFR：穩定、零 warning）。
# 需有 recipe 才能覆寫 Makefile.inc 的通用 lint（否則只是追加前置相依）。
lint: fmt-check clippy
	@echo "✓ lint passed（fmt + clippy，零 warning）"

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
