"""DLL 用途说明词典：外置 assets/dll_meanings.json + 查询入口。

词典格式：``{小写 DLL 名: 中文用途说明}``。
加载策略与 pe_risks / pe_translations 一致：外置优先、失败记告警并回退
（不再静默 pass）——报告里 import 表"用途"列整列为空时，用户必须能看到
"词典没加载上"，而不是以为这些 DLL 都没收录。

拆分自原 achieve/pe_parser.py（2026-10-18）。
"""

from __future__ import annotations

import json
from pathlib import Path

from .pe_models import LOAD_WARNINGS

# 外置词典路径（项目根 assets/ 下）
DLL_MEANINGS_PATH = Path(__file__).resolve().parent.parent / "assets" / "dll_meanings.json"

# 内置为空（说明性数据纯外置）；加载失败时仅记录告警
_BUILTIN_DLL_MEANINGS: dict[str, str] = {}


def _load_dll_meanings() -> dict[str, str]:
    """从 assets/dll_meanings.json 加载 DLL 用途说明词典（key 统一小写）。"""
    try:
        with DLL_MEANINGS_PATH.open(encoding="utf-8") as fh:
            raw = json.load(fh)
    except FileNotFoundError:
        LOAD_WARNINGS.append(("warn.dll_missing", {}))
        return dict(_BUILTIN_DLL_MEANINGS)
    except (OSError, json.JSONDecodeError) as exc:
        LOAD_WARNINGS.append(("warn.dll_load_failed", {"err": exc}))
        return dict(_BUILTIN_DLL_MEANINGS)

    if not isinstance(raw, dict):
        LOAD_WARNINGS.append(("warn.dll_bad_root", {}))
        return dict(_BUILTIN_DLL_MEANINGS)

    out: dict[str, str] = {}
    for key, value in raw.items():
        k = str(key).strip().lower()
        if not k or k.startswith("_"):
            continue
        if isinstance(value, str) and value:
            out[k] = value
    return out or dict(_BUILTIN_DLL_MEANINGS)


DLL_MEANINGS: dict[str, str] = _load_dll_meanings()


def dll_meaning(name: str) -> str:
    """查 DLL 用途说明；未收录返回空串。名称统一小写、去空白后匹配。"""
    if not name:
        return ""
    return DLL_MEANINGS.get(name.strip().lower(), "")
