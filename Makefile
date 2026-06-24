# CyTrace — 專案 Makefile
#
# ASP 指令（autopilot-* / adr-new / spec-new / audit-health / asp-gate …）來自
# user-level 安裝的 ~/.claude/asp/Makefile.inc（v5 共用層；不在專案內複製）。
#
# 常用：
#   make autopilot-init       產生 ROADMAP.yaml 範本
#   make autopilot-validate   驗證 ROADMAP.yaml 結構並同步 CLAUDE.md
#   make autopilot-status     查看 autopilot 進度
#   make adr-new TITLE="..."  新增 ADR
#   make spec-new TITLE="..." 新增 SPEC
#   make audit-health         專案健康審計
#
# 產品自身的 build/test/lint 目標待 M0 由 autopilot 建立（Rust workspace + 前端）。

-include $(HOME)/.claude/asp/Makefile.inc

.PHONY: info
info:
	@echo "CyTrace — 地端依賴風險報表產生器"
	@echo "================================="
	@echo "ASP 指令見 'make help'（來自 ~/.claude/asp/Makefile.inc：autopilot-validate 等）"
	@echo "產品 build/test/lint 目標將於 ROADMAP M0 建立。"
