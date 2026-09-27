#!/usr/bin/env python3
"""i18n 鍵一致性檢查（NFR-06 / ADR-004）。

遞迴比對 locales/*.json 的**葉鍵集合**（巢狀命名空間），確保兩語系鍵完全一致、無缺鍵。
ASP 內建 make i18n-check 只比頂層鍵數量，守不住巢狀；本檢查補足。退出碼非 0 即失敗（供 CI）。
"""
import json
import pathlib
import re
import sys
from pathlib import Path

LOCALES = Path(__file__).resolve().parent.parent / "locales"
FILES = {"zh-TW": LOCALES / "zh-TW.json", "en-US": LOCALES / "en-US.json"}


def leaf_keys(obj, prefix=""):
    keys = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            keys |= leaf_keys(v, f"{prefix}{k}.")
    else:
        keys.add(prefix.rstrip("."))
    return keys


# 程式碼中出現的字面 i18n 鍵（`"cbom.err.timeout"` 之類）必須存在於 catalog。
# 只比對兩語系對稱抓不到「根本沒進 catalog 的鍵」——第五輪複審即因此漏掉 cbom.err.* 七鍵。
# 排除檔名等非鍵字面值（.html/.json/.js/.css 結尾）
_NS = r"(?:cbom\.err|cli|report|crypto|severity|server|console)"
_NOT_FILE = r"(?!html|json|js|css|md)"
# 雙引號（Rust）、單引號與反引號（前端）皆須涵蓋——前端一律單引號，
# 只認雙引號等於對前端零覆蓋（第六輪複審 finding F）。
KEY_LITERAL = re.compile(
    rf"""['"`]({_NS}\.{_NOT_FILE}[a-z0-9_.]+)['"`]"""
)
# 模板字串組鍵：t(`report.crypto.col.${{c}}`) → 取前綴，要求 catalog 有該前綴下的葉鍵
KEY_PREFIX = re.compile(rf"`({_NS}(?:\.[a-z0-9_]+)*)\.\$\{{")
CODE_GLOBS = ("crates/**/*.rs", "frontend/src/**/*.ts", "frontend/src/**/*.tsx")


def keys_used_in_code(root: pathlib.Path) -> tuple[set[str], set[str]]:
    """回傳（字面鍵, 模板前綴）。"""
    keys: set[str] = set()
    prefixes: set[str] = set()
    for pattern in CODE_GLOBS:
        for f in root.glob(pattern):
            if "/tests/" in str(f) or f.name.endswith("_test.rs"):
                continue
            text = f.read_text(encoding="utf-8")
            keys |= set(KEY_LITERAL.findall(text))
            prefixes |= set(KEY_PREFIX.findall(text))
    return keys, prefixes


def main() -> int:
    sets = {}
    for lang, path in FILES.items():
        if not path.exists():
            print(f"✗ 缺少 locale: {path}")
            return 1
        sets[lang] = leaf_keys(json.loads(path.read_text(encoding="utf-8")))

    base = sets["zh-TW"]
    ok = True
    for lang, keys in sets.items():
        missing = base - keys
        extra = keys - base
        if missing or extra:
            ok = False
            print(f"✗ {lang}: 缺 {sorted(missing)} 多 {sorted(extra)}")
    # 反向檢查：程式碼引用的鍵必須在 catalog 中
    root = pathlib.Path(__file__).resolve().parent.parent
    used, prefixes = keys_used_in_code(root)
    undefined = sorted(k for k in used if k not in base)
    if undefined:
        ok = False
        print(f"✗ 程式碼引用但 catalog 未定義的鍵：{undefined}")
    # 模板前綴：catalog 至少要有該前綴下的葉鍵，否則整組動態鍵都查不到
    empty_prefixes = sorted(
        p for p in prefixes if not any(k.startswith(p + ".") for k in base)
    )
    if empty_prefixes:
        ok = False
        print(f"✗ 模板字串前綴在 catalog 下無任何葉鍵：{empty_prefixes}")

    if ok:
        print(
            f"✓ i18n 鍵一致（{len(base)} 個葉鍵 × {len(FILES)} 語系，無缺鍵；"
            f"程式碼引用 {len(used)} 鍵 + {len(prefixes)} 模板前綴皆已定義）"
        )
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
