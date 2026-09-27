#!/usr/bin/env python3
"""打包腳本 NOTICE 對帳（ADR-013 / 供應鏈純淨鐵則）。

`package.sh`（Linux）與 `package.ps1`（Windows）各自生成 NOTICE，
兩份是分別維護的文字——**改一邊忘一邊就會出一個授權聲明不實的交付包**。
第六輪複審 finding J 即為此：ps1 整段漏了 ring 的 ISC + OpenSSL/BoringSSL
混合授權聲明，而 Windows 交付同樣含 cytrace serve、同樣連結 ring。

本檢查不比對逐字（兩份本就一中一英），只要求下列**法律上必須出現的實體**
在兩支腳本中皆被提及。CI 的 windows-package job 另有對「產出物」的斷言；
本檢查在 lint 階段先擋住原始碼層的不對稱，無須跑完整打包。
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SH = ROOT / "scripts" / "package.sh"
PS1 = ROOT / "scripts" / "package.ps1"

# 每一項：(說明, sh 需含的 pattern, ps1 需含的 pattern)
# 分列兩欄是因為兩份 NOTICE 一中一英；共用的專有名詞才寫同一字串。
REQUIRED = [
    ("Syft 授權", r"Syft", r"Syft"),
    ("Grype 授權", r"Grype", r"Grype"),
    ("theia 授權（條件段）", r"CBOMkit-theia", r"CBOMkit-theia"),
    ("theia 相依 MPL-2.0 標示", r"MPL-2\.0", r"MPL-2\.0"),
    ("theia 相依 gitleaks MIT 標示", r"gitleaks", r"gitleaks"),
    ("theia 缺席時的明示降級", r"不含 CBOM 引擎", r"does not include the CBOM engine"),
    ("ring 混合授權（ISC + OpenSSL/BoringSSL）", r"\bring\b", r"\bring\b"),
    ("ring 的 OpenSSL/BoringSSL 條款", r"OpenSSL/BoringSSL", r"OpenSSL/BoringSSL"),
    ("rustls（TLS 提供者）", r"rustls", r"rustls"),
    ("自產 SBOM 交叉引用", r"cytrace\.sbom\.cdx\.json", r"cytrace\.sbom\.cdx\.json"),
    ("禁中國來源宣告", r"OpenSCA-cli", r"OpenSCA-cli"),
    ("該宣告的涵蓋範圍註記", r"國籍", r"does not cover the nationality"),
    ("cargo-deny 把關聲明", r"cargo-deny", r"cargo-deny"),
]


def main() -> int:
    missing = []
    for path in (SH, PS1):
        if not path.exists():
            print(f"✗ 缺少打包腳本: {path}")
            return 1
    sh_text = SH.read_text(encoding="utf-8")
    ps1_text = PS1.read_text(encoding="utf-8")

    for label, sh_pat, ps1_pat in REQUIRED:
        if not re.search(sh_pat, sh_text):
            missing.append(f"package.sh 缺「{label}」")
        if not re.search(ps1_pat, ps1_text):
            missing.append(f"package.ps1 缺「{label}」")

    if missing:
        print("✗ 兩平台 NOTICE 不對稱——會出授權聲明不實的交付包：")
        for m in missing:
            print(f"    - {m}")
        return 1

    print(f"✓ NOTICE 對帳通過（{len(REQUIRED)} 項法律必要實體，Linux / Windows 皆具備）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
