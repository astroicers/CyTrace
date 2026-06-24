#!/usr/bin/env python3
"""i18n 鍵一致性檢查（NFR-06 / ADR-004）。

遞迴比對 locales/*.json 的**葉鍵集合**（巢狀命名空間），確保兩語系鍵完全一致、無缺鍵。
ASP 內建 make i18n-check 只比頂層鍵數量，守不住巢狀；本檢查補足。退出碼非 0 即失敗（供 CI）。
"""
import json
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
    if ok:
        print(f"✓ i18n 鍵一致（{len(base)} 個葉鍵 × {len(FILES)} 語系，無缺鍵）")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
