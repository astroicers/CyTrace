#!/usr/bin/env python3
"""手動補發（workflow_dispatch 帶 tag 輸入）時，每個 checkout 都必須取那個 tag（#61）。

`actions/checkout` 不指定 `ref` 時，checkout 的是觸發時選的分支（預設 main），不是輸入的 tag。
手動補發 vX.Y.Z 時，Release 的執行檔就可能由 main 編出——而 main 的 Cargo.toml 版號未變時，
release.yml 的版號核對與 package.ps1 -CytraceExe 的自報版本核對都攔不住（DELIVERY_SOP §2 的前提失效）。

規則：`on.workflow_dispatch.inputs` 含 `tag` 的 workflow，其中每個 `uses: actions/checkout@…` 步驟都必須有
`with.ref`，且**逐字等於** CANONICAL：
- 手動補發時只認 `refs/tags/<tag>`（不會被同名分支搶走）；
- 其他觸發時為空字串，checkout 走預設行為（取觸發的 ref 並釘住 github.sha），與不寫 ref 等價。
只比子字串的話，`${{ github.ref || github.event.inputs.tag }}`（永遠取 github.ref）、`inputs.tags` 這類寫法都會誤判通過。

不依賴 PyYAML（runner 與離線 build 機不保證有；與 release-notes.py 同一做法）：以縮排界定 step 區塊。

反空轉：
- 先對內建樣本自測：壞樣本必須判錯、好樣本不得判錯；
- 實際掃描必須偵測到 EXPECTED 中的每個 workflow 都帶 tag 輸入、且各有至少一個 checkout——
  某個 workflow 的輸入被改名而被靜默排除時，本檢查會失敗，而不是少檢一個檔照樣綠燈。
退出碼非 0 即失敗（供 make lint 與 CI）。
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"
EXPECTED = {"release.yml", "docker.yml"}
CANONICAL = "${{ github.event.inputs.tag && format('refs/tags/{0}', github.event.inputs.tag) || '' }}"


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _significant(line: str) -> bool:
    s = line.strip()
    return bool(s) and not s.startswith("#")


def _block_after(lines: list[str], i: int) -> list[str]:
    """第 i 行（一個映射鍵）底下縮排較深的區塊。"""
    base = _indent(lines[i])
    out = []
    for t in lines[i + 1 :]:
        if _significant(t) and _indent(t) <= base:
            break
        out.append(t)
    return out


def has_dispatch_tag(text: str) -> bool:
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if not re.match(r"^\s*workflow_dispatch:\s*$", line):
            continue
        block = _block_after(lines, i)
        for j, t in enumerate(block):
            if re.match(r"^\s*inputs:\s*$", t):
                inner = [s for s in _block_after(block, j) if _significant(s)]
                if inner:
                    first = _indent(inner[0])
                    if any(_indent(s) == first and re.match(r"^\s*['\"]?tag['\"]?\s*:", s) for s in inner):
                        return True
    return False


def checkout_refs(text: str) -> list[tuple[int, str | None]]:
    """每個 actions/checkout 步驟：(行號, with.ref 的值；沒有則 None)。"""
    lines = text.splitlines()
    found = []
    for i, line in enumerate(lines):
        m = re.match(r"^(\s*)(-\s+)?uses:\s*['\"]?actions/checkout@", line)
        if not m:
            continue
        k = len(m.group(1)) + len(m.group(2) or "")  # step 映射的鍵所在欄
        dash = re.compile(r"^\s{%d}-\s" % (k - 2))
        lo = i
        while lo > 0 and not dash.match(lines[lo]):
            lo -= 1
        hi = i + 1
        while hi < len(lines) and not (_significant(lines[hi]) and _indent(lines[hi]) < k):
            hi += 1
        block = lines[lo:hi]
        ref = None
        with_re = re.compile(r"^(\s{%d}|\s{%d}-\s+)with:\s*$" % (k, k - 2))
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
                rm = re.match(r"^\s*ref\s*:\s*(.*?)\s*$", t)
                if _indent(t) == inner and rm:
                    v = rm.group(1)
                    if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
                        v = v[1:-1]
                    ref = v
        found.append((i + 1, ref))
    return found


def check(text: str, name: str) -> tuple[list[str], int]:
    """回傳（錯誤清單, 檢查過的 checkout 數）。沒有 dispatch tag 輸入的 workflow 不檢查。"""
    if not has_dispatch_tag(text):
        return [], 0
    errs = []
    refs = checkout_refs(text)
    for lineno, ref in refs:
        if ref != CANONICAL:
            errs.append(f"{name}:{lineno} checkout 的 ref 不是標準寫法（現為 {ref if ref is not None else '未指定'}）")
    return errs, len(refs)


def self_test() -> tuple[list[str], int]:
    head = "on:\n  workflow_dispatch:\n    inputs:\n      tag:\n        required: true\njobs:\n  b:\n    steps:\n"
    co = "      - uses: actions/checkout@v4\n        with:\n          ref: {}\n"
    bad = {
        "缺 ref": head + "      - uses: actions/checkout@v4\n",
        "ref 為分支": head + co.format("main"),
        "順序顛倒（永遠取 github.ref）": head + co.format("${{ github.ref || github.event.inputs.tag }}"),
        "相似名稱 inputs.tags": head + co.format(CANONICAL.replace("inputs.tag ", "inputs.tags ")),
        "舊寫法（不釘 commit）": head + co.format("${{ github.event.inputs.tag || github.ref }}"),
        "uses 非首鍵且缺 ref": head + "      - name: x\n        uses: actions/checkout@v4\n",
        "以 SHA 釘版且缺 ref": head + "      - uses: actions/checkout@0123456789abcdef\n",
    }
    good = {
        "標準寫法": head + co.format(CANONICAL),
        "標準寫法（加引號）": head + co.format('"' + CANONICAL + '"'),
        "uses 非首鍵的標準寫法": head + "      - name: x\n        uses: actions/checkout@v4\n        with:\n          ref: " + CANONICAL + "\n",
        "沒有 tag 輸入": "on:\n  push:\njobs:\n  b:\n    steps:\n      - uses: actions/checkout@v4\n",
    }
    errs = []
    for label, text in bad.items():
        if not check(text, label)[0]:
            errs.append(f"自測：壞樣本「{label}」未被判錯")
    for label, text in good.items():
        if check(text, label)[0]:
            errs.append(f"自測：好樣本「{label}」被誤判")
    return errs, len(bad) + len(good)


def main() -> int:
    errs, cases = self_test()
    detected: dict[str, int] = {}
    for path in sorted(WORKFLOWS.glob("*.y*ml")):
        text = path.read_text(encoding="utf-8")
        e, n = check(text, str(path.relative_to(ROOT)))
        errs += e
        if has_dispatch_tag(text):
            detected[path.name] = n
    for name in sorted(EXPECTED):
        if name not in detected:
            errs.append(f"{name} 未被偵測為帶 tag 輸入的 workflow_dispatch——輸入若改名，請同步更新本檢查")
        elif detected[name] == 0:
            errs.append(f"{name} 找不到任何 checkout 步驟——本檢查對它已失去作用")
    if errs:
        print("✗ 手動補發的 checkout ref 檢查失敗（#61）：")
        for e in errs:
            print(f"  {e}")
        return 1
    total = sum(detected.values())
    print(f"✓ 手動補發皆 checkout 指定的 tag（{len(detected)} 個 workflow、{total} 個 checkout；自測 {cases} 例皆判對）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
