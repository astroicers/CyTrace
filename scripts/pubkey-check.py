#!/usr/bin/env python3
"""交付簽章公鑰的單一事實源檢查（ADR-007 信任錨；T402）。

`keys/cytrace.pub` 是 minisign 公鑰檔，目標場域靠帶外抄錄的同一串公鑰驗章。
文件裡抄錯一個字元，場域驗章就必然失敗——而且失敗時操作員無從判斷是包被竄改還是文件抄錯。
本檢查確認：

1. 公鑰檔格式正確：兩行；第一行為 `untrusted comment:`；第二行 base64 解出 42 bytes，
   以 `Ed` 起頭（Ed25519），其後 8 bytes 的金鑰 ID 與註解中的 ID 一致。
2. `docs/DELIVERY_SOP.md` 與 `README.md` 抄錄的公鑰字串與金鑰 ID 都等於公鑰檔的值。

反空轉：先對內建的壞樣本自測（格式錯、ID 不符、文件抄錯），每一種都必須被判錯。
退出碼非 0 即失敗（供 make lint 與 CI）。
"""
import base64
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PUBKEY = ROOT / "keys" / "cytrace.pub"
DOCS = [ROOT / "docs" / "DELIVERY_SOP.md", ROOT / "README.md"]


def parse_pubkey(text: str) -> tuple[str, str]:
    """回傳（公鑰字串, 金鑰 ID 十六進位大寫）；格式不符時 raise ValueError。"""
    lines = text.strip("\n").split("\n")
    if len(lines) != 2:
        raise ValueError(f"應為兩行，實得 {len(lines)} 行")
    comment, key = lines[0], lines[1].strip()
    if not comment.startswith("untrusted comment:"):
        raise ValueError("第一行應以 `untrusted comment:` 起頭")
    try:
        raw = base64.b64decode(key, validate=True)
    except ValueError as e:
        raise ValueError(f"第二行不是合法 base64：{e}") from None
    if len(raw) != 42 or raw[:2] != b"Ed":
        raise ValueError(f"不是 minisign Ed25519 公鑰（{len(raw)} bytes，前綴 {raw[:2]!r}）")
    key_id = raw[2:10][::-1].hex().upper()  # minisign 以 little-endian 顯示金鑰 ID
    if key_id not in comment:
        raise ValueError(f"註解中的金鑰 ID 與公鑰不符（公鑰為 {key_id}）")
    return key, key_id


def check_docs(key: str, key_id: str, docs: dict[str, str]) -> list[str]:
    errs = []
    for name, text in docs.items():
        if key not in text:
            errs.append(f"{name} 未抄錄公鑰 {key}（或抄錯）")
        if key_id not in text:
            errs.append(f"{name} 未寫金鑰 ID {key_id}")
    return errs


def self_test(key: str, key_id: str) -> list[str]:
    """壞樣本必須被判錯；任一沒被抓到，代表本檢查已經失去鑑別力。"""
    errs = []
    raw = base64.b64decode(key)
    other = base64.b64encode(raw[:2] + bytes(8) + raw[10:]).decode()
    bad_files = {
        "只有一行": key,
        "缺 untrusted comment": f"comment\n{key}",
        "非 base64": "untrusted comment: x\n!!!!",
        "長度不對": f"untrusted comment: x\n{base64.b64encode(raw[:30]).decode()}",
        "ID 不符": f"untrusted comment: minisign public key {key_id}\n{other}",
    }
    for name, text in bad_files.items():
        try:
            parse_pubkey(text)
            errs.append(f"自測：壞公鑰檔「{name}」未被判錯")
        except ValueError:
            pass
    flipped = key[:-2] + ("A" if key[-2] != "A" else "B") + key[-1]
    if not check_docs(key, key_id, {"抄錯一字元": f"{flipped} {key_id}"}):
        errs.append("自測：文件抄錯一個字元未被判錯")
    if check_docs(key, key_id, {"正確抄錄": f"{key} {key_id}"}):
        errs.append("自測：正確抄錄被誤判")
    return errs


def main() -> int:
    try:
        key, key_id = parse_pubkey(PUBKEY.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        print(f"✗ {PUBKEY.relative_to(ROOT)}：{e}")
        return 1
    errs = self_test(key, key_id)
    errs += check_docs(
        key,
        key_id,
        {str(p.relative_to(ROOT)): p.read_text(encoding="utf-8") for p in DOCS},
    )
    if errs:
        print("✗ 交付簽章公鑰檢查失敗：")
        for e in errs:
            print(f"  {e}")
        return 1
    print(f"✓ 交付簽章公鑰一致（金鑰 ID {key_id}；{len(DOCS)} 份文件抄錄相符；自測 7 例皆判對）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
