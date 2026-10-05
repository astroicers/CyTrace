#!/usr/bin/env python3
"""GitHub Release 說明的單一產生器（CHANGELOG.md 為唯一事實源）。

    python3 scripts/release-notes.py render v0.3.0 > release-notes.md   # release.yml 用
    python3 scripts/release-notes.py check                              # CI / make lint 用

為什麼需要它——v0.3.0 的 Release 頁實際壞過兩次：

1. **說明被整份覆蓋**。release.yml 與 docker.yml 都以 softprops/action-gh-release 寫同一個
   Release，而該 action 更新既有 release 時 `body = workflowBody || existingBody`
   （v2 / 3bb12739 src/github.ts:560–567）——docker.yml 給了三行映像說明，於是 release.yml
   寫的整份說明（含「已知限制」）被蓋掉，公開頁只剩三行。
2. **已知限制寫死在 workflow 裡**。release.yml 的 body 內含「已知限制（v0.3.0）」逐字清單，
   下一版發布時會原樣印出上一版的限制（包括已修掉的那條），而 CHANGELOG 才是被維護的那份。

故：說明一律由本腳本自 CHANGELOG 該版段落組出，只有 release.yml 可以寫 body；
`check` 機械擋住「別的 workflow 又給了 body」與「CHANGELOG 缺當前版本段落」。
"""
from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"
# 唯一准許寫 Release 說明的 workflow
BODY_OWNER = "release.yml"
ACTION = "softprops/action-gh-release"
BODY_KEYS = {"body", "body_path", "append_body"}

HEADER = """\
CyTrace {tag} — 雙平台執行檔（ADR-010）＋容器映像（ADR-012）

| 檔案 | 說明 |
|------|------|
| `cytrace-x86_64-linux` | Linux x86_64，musl 靜態 binary，零 runtime 依賴 |
| `cytrace-x86_64-windows.exe` | Windows x86_64，msvc 靜態 CRT，免 VC++ 可轉散發套件 |
| `cbomkit-theia-windows-amd64.exe` | CBOM 引擎 Windows 版（自源碼交叉編譯；放到 `dist\\cbomkit-theia.exe` 供 `package.ps1` 打包，見 docs/DELIVERY_SOP.md §2） |
| `SHA256SUMS` | 執行檔校驗（`sha256sum -c SHA256SUMS`） |
| `cytrace-*-image.tar` | 容器映像（由 Docker workflow 另掛；離線搬運見 docs/DELIVERY_SOP.md §7） |
| `SHA256SUMS-image` | 映像校驗（`sha256sum -c SHA256SUMS-image`；與執行檔的 `SHA256SUMS` 是兩份） |
| `IMAGE_DIGEST.txt` | 映像 digest（與 GHCR 上的映像比對） |
| `cytrace-image.sbom.cdx.json` | 映像本身的 SBOM（CycloneDX） |

> 本 Release 不含 air-gapped **安裝包**：安裝包由交付端逐平台產生（Linux `make package`、
> Windows `pwsh scripts/package.ps1`；見 docs/DELIVERY_SOP.md §2）。**各平台安裝包含哪些
> 引擎，以下方「已知限制」為準。** 交付工作站以 minisign 簽章（私鑰不進 CI）。

## 變更內容（摘自 CHANGELOG.md）
"""

SECTION_RE = re.compile(r"^## \[(?P<ver>[^\]]+)\](?P<rest>.*)$")
DATED_RE = re.compile(r"^\s*-\s*\d{4}-\d{2}-\d{2}\s*$")


def changelog_section(text: str, version: str) -> tuple[str, str]:
    """回傳 (標頭行其餘部分, 段落內文)。找不到 → ValueError。"""
    lines = text.splitlines()
    start = None
    for i, line in enumerate(lines):
        m = SECTION_RE.match(line)
        if m and m.group("ver") == version:
            start = i
            rest = m.group("rest")
            break
    if start is None:
        raise ValueError(f"CHANGELOG.md 沒有 `## [{version}]` 段落")
    body = []
    for line in lines[start + 1 :]:
        if SECTION_RE.match(line):
            break
        body.append(line)
    content = "\n".join(body).strip()
    if not content:
        raise ValueError(f"CHANGELOG.md 的 `## [{version}]` 段落是空的")
    return rest, content


def render(tag: str, changelog: str) -> str:
    version = tag.removeprefix("v")
    rest, content = changelog_section(changelog, version)
    # 發布時標頭必須帶日期——v0.3.0 曾把 tag 打在「未發布」上（PR #19 才補）
    if not DATED_RE.match(rest):
        raise ValueError(
            f"`## [{version}]{rest}` 未標發布日期（應為 `## [{version}] - YYYY-MM-DD`）"
        )
    return HEADER.format(tag=f"v{version}") + "\n" + content + "\n"


def _indent(s: str) -> int:
    return len(s) - len(s.lstrip())


def _significant(s: str) -> bool:
    return bool(s.strip()) and not s.lstrip().startswith("#")


def release_steps(text: str) -> list[tuple[int, set[str]]]:
    """找出 workflow 文字中每個使用 ACTION 的 step，回傳 (行號, with 底下的第一層鍵)。

    不依賴 PyYAML（runner 與離線 build 機不保證有）。以縮排界定區塊：step 映射的鍵在第 k 欄
    （`- uses:` 時 k = 破折號欄 + 2）；step 從其 `- ` 行起、到下一個縮排 < k 的有效行為止；
    `with:` 位於第 k 欄，其下第一層縮排的鍵即為輸入。正負對照見 self_test。
    """
    lines = text.splitlines()
    found = []
    for i, line in enumerate(lines):
        m = re.match(r"^(\s*)(-\s+)?uses:\s*['\"]?" + re.escape(ACTION) + r"\b", line)
        if not m:
            continue
        k = len(m.group(1)) + len(m.group(2) or "")
        dash = re.compile(r"^\s{%d}-\s" % (k - 2))
        lo = i
        while lo > 0 and not dash.match(lines[lo]):
            lo -= 1
        hi = i + 1
        while hi < len(lines) and not (_significant(lines[hi]) and _indent(lines[hi]) < k):
            hi += 1
        block = lines[lo:hi]
        with_re = re.compile(r"^(\s{%d}|\s{%d}-\s+)with:\s*$" % (k, k - 2))
        keys: set[str] = set()
        for j, s in enumerate(block):
            if not with_re.match(s):
                continue
            inner = None
            for t in block[j + 1 :]:
                if not _significant(t):
                    continue
                if _indent(t) <= k:
                    break
                inner = _indent(t) if inner is None else inner
                km = re.match(r"^\s*([A-Za-z_][\w-]*)\s*:", t)
                if _indent(t) == inner and km:
                    keys.add(km.group(1))
        found.append((i + 1, keys))
    return found


SAMPLE_OK = """\
jobs:
  a:
    steps:
      - name: 附掛
        uses: softprops/action-gh-release@v2
        with:
          tag_name: x
          files: |
            body.txt
      - run: echo body
"""
SAMPLE_BAD = """\
jobs:
  a:
    steps:
      - name: 附掛
        uses: softprops/action-gh-release@v2
        with:
          tag_name: x
          body: |
            three lines
"""
SAMPLE_CL = """\
## [Unreleased]

## [1.2.0] - 2026-01-02

### 新增
- 甲

## [1.1.0] - 未發布

- 乙

## [1.0.0] - 2025-12-01
"""


def self_test() -> list[str]:
    """解析器的正負對照：壞樣本必中、好樣本必不中。解析器失效時 check 不得空轉為綠。"""
    errs = []
    ok = release_steps(SAMPLE_OK)
    if len(ok) != 1 or ok[0][1] != {"tag_name", "files"}:
        errs.append(f"自檢：好樣本應抽出 {{tag_name, files}}，得到 {ok}")
    bad = release_steps(SAMPLE_BAD)
    if len(bad) != 1 or "body" not in bad[0][1]:
        errs.append(f"自檢：壞樣本的 body 沒被抽到：{bad}")
    try:
        r = render("v1.2.0", SAMPLE_CL)
        if "- 甲" not in r or "1.0.0" in r or "乙" in r:
            errs.append("自檢：段落截取範圍錯誤")
    except ValueError as e:
        errs.append(f"自檢：有日期的段落不應失敗：{e}")
    for tag, why in (("v1.1.0", "未標日期"), ("v9.9.9", "不存在")):
        try:
            render(tag, SAMPLE_CL)
            errs.append(f"自檢：{why}的段落（{tag}）應失敗卻通過")
        except ValueError:
            pass
    return errs


def cargo_version() -> str:
    text = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
    m = re.search(r'^version\s*=\s*"([^"]+)"', text, re.M)
    if not m:
        raise SystemExit("✗ 讀不到 Cargo.toml 的 version")
    return m.group(1)


def check() -> int:
    errs = self_test()

    # 1. 只有 BODY_OWNER 可以寫 Release 說明
    steps = []
    for wf in sorted(WORKFLOWS.glob("*.y*ml")):
        for line, keys in release_steps(wf.read_text(encoding="utf-8")):
            steps.append((wf.name, line, keys))
    for name, line, keys in steps:
        if name != BODY_OWNER and keys & BODY_KEYS:
            errs.append(
                f"{name}:{line} 對 {ACTION} 給了 {sorted(keys & BODY_KEYS)}——"
                f"更新既有 release 時會整份覆蓋 {BODY_OWNER} 寫的說明；只附掛 files"
            )
    # 反空轉：兩個 workflow 都必須被看到，且說明的擁有者確實以 body_path 取用本腳本產物
    owners = [k for n, _, k in steps if n == BODY_OWNER]
    if len(steps) < 2:
        errs.append(f"只找到 {len(steps)} 個 {ACTION} step（預期 release.yml 與 docker.yml 各一）——解析可能失效")
    if len(owners) != 1 or "body_path" not in owners[0] or "body" in owners[0]:
        errs.append(f"{BODY_OWNER} 應恰有一個 {ACTION} step 且以 body_path 取用本腳本產物：{owners}")

    # 2. 當前版本在 CHANGELOG 必須有非空段落（版本號 bump 時同一個 PR 就得寫好）
    version = cargo_version()
    try:
        changelog_section((ROOT / "CHANGELOG.md").read_text(encoding="utf-8"), version)
    except ValueError as e:
        errs.append(str(e))

    if errs:
        print("✗ Release 說明檢查失敗：\n  " + "\n  ".join(errs), file=sys.stderr)
        return 1
    print(
        f"✓ Release 說明檢查通過（{len(steps)} 個 {ACTION} step，僅 {BODY_OWNER} 寫說明；"
        f"CHANGELOG 有 [{version}] 段落；解析器正負對照 5 例）"
    )
    return 0


def main(argv: list[str]) -> int:
    if len(argv) == 2 and argv[1] == "check":
        return check()
    if len(argv) == 3 and argv[1] == "render":
        errs = self_test()
        if errs:
            print("✗ " + "\n  ".join(errs), file=sys.stderr)
            return 1
        try:
            sys.stdout.write(render(argv[2], (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")))
        except ValueError as e:
            print(f"✗ {e}", file=sys.stderr)
            return 1
        return 0
    print(__doc__.split("\n\n")[1], file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
