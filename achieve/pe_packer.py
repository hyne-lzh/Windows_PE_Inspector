"""打包器识别：按节区名 + 特征字符串双证据判定。

判定策略：
- 节区名：全等或前缀匹配（如 ``.vmp0``）
- 特征字符串：子串匹配；只扫描前 PACKER_SCAN_LIMIT 条，避免超大样本卡顿

注意（已知局限）：字符串只扫前 2 万条，若样本在该数量之前已塞入大量字符串，
可能漏掉靠后的特征串——此时仍可能靠节区名命中，但"仅字符串证据"的场景会漏报。

拆分自原 achieve/pe_parser.py（2026-10-18）。
"""

from __future__ import annotations

from .pe_format import PACKER_SCAN_LIMIT
from .pe_models import PackerHit

# (打包器名, 节区名特征(小写/前缀匹配), 特征字符串(小写/子串匹配))
_PACKER_SIGNATURES: tuple[tuple[str, tuple[str, ...], tuple[str, ...]], ...] = (
    ("UPX",         ("upx0", "upx1", "upx2"), ("upx!", "upx0", "upx1")),
    ("PyInstaller", ("pyi-",), ("pyi-", "pyinstaller", "_meipass", "pyz-00.pyz", "pyiboot")),
    ("Nuitka",      ("nuitka",), ("__nuitka", "nuitka-onefile", "nuitka-python", "nuitka_onefile")),
    ("VMProtect",   (".vmp0", ".vmp1", ".vmp2", ".vmp"), ("vmprotect", ".vmp0", ".vmp1")),
    ("Themida",     (".themida", ".winlice"), ("themida", "winlicense")),
    ("ASPack",      (".aspack", ".adata"), ("aspack",)),
    ("MPRESS",      (".mpress1", ".mpress2"), ("mpress1", "mpress2")),
    ("PECompact",   ("pec1", "pec2", "pec3"), ("pecompact",)),
    ("Enigma",      (".enigma1", ".enigma2"), ("enigma prot",)),
    ("WinUpack",    (".upack",), (".upack",)),
)


def detect_packers(section_names: list[str], strings: list[str]) -> list[PackerHit]:
    """根据节区名与特征字符串识别打包器。"""
    sec_lower = [s.strip().lower() for s in (section_names or []) if s and s.strip()]

    scan: set[str] = set()
    for s in (strings or [])[:PACKER_SCAN_LIMIT]:
        if s:
            sl = s.strip().lower()
            if sl:
                scan.add(sl)

    hits: list[PackerHit] = []
    for name, sec_keys, str_keys in _PACKER_SIGNATURES:
        sec_hits: list[str] = []
        for key in sec_keys:
            for actual in sec_lower:
                if (actual == key or actual.startswith(key)) and actual not in sec_hits:
                    sec_hits.append(actual)
        str_hits: list[str] = []
        for key in str_keys:
            if any(key in s for s in scan) and key not in str_hits:
                str_hits.append(key)
        if sec_hits or str_hits:
            hits.append(PackerHit(name=name, sections=sec_hits, strings=str_hits))
    return hits
