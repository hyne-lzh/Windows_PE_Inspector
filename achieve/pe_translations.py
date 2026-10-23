"""PE 结构值翻译：内置表 + 外置 assets/translations.json 合并 + 通用查找入口。

与 achieve/i18n.py 的分工：
- ``i18n.py`` 管**界面文案**（t(key) → 一句话，支持占位符）
- 本模块管**PE 结构标识的中英说明**（translate(category, key) → 一段说明），
  覆盖架构 / 子系统 / 节区权限 / 调试类型 / 高危分类五类。

设计要点：
- 内置为底、外置按分类覆盖，用户改 JSON 即可扩充，无需动代码；
- 外置文件缺失**不告警**（本就是可选项），损坏/结构错误才记 LOAD_WARNINGS；
- 查找顺序：指定语言 → 中文 → default，任一步命中即返回，绝不抛异常。

拆分自原 achieve/pe_parser.py（2026-10-18）。
"""

from __future__ import annotations

import json
from pathlib import Path

from .i18n import get_language
from .pe_models import LOAD_WARNINGS

# --------------------------------------------------------------------------
# 通用翻译表（PE 各分类的英文标识 → 各语言说明）
# --------------------------------------------------------------------------
# 每个条目的值统一为 {语言代码: 文本}，例如 {"zh": "代码", "en": "Code"}。
# 新增分类只需往 _BUILTIN_TRANSLATIONS 加一个键，然后调用
# translate("分类", key, lang=...) 即可。
# --------------------------------------------------------------------------
_BUILTIN_TRANSLATIONS: dict[str, dict[str, dict[str, str]]] = {
    "SECTION_FLAGS": {
        "CODE": {"zh": "代码", "en": "Code"},
        "IDATA": {"zh": "已初始化数据", "en": "Initialized data"},
        "UDATA": {"zh": "未初始化数据", "en": "Uninitialized data"},
        "X": {"zh": "可执行", "en": "Executable"},
        "R": {"zh": "可读", "en": "Readable"},
        "W": {"zh": "可写", "en": "Writable"},
    },
    "MACHINE": {
        "IMAGE_FILE_MACHINE_AMD64": {"zh": "x64 64 位", "en": "x64 (64-bit)"},
        "IMAGE_FILE_MACHINE_I386": {"zh": "x86 32 位", "en": "x86 (32-bit)"},
        "IMAGE_FILE_MACHINE_IA64": {"zh": "IA64 安腾", "en": "IA64 Itanium"},
        "IMAGE_FILE_MACHINE_ARM": {"zh": "ARM 32 位", "en": "ARM (32-bit)"},
        "IMAGE_FILE_MACHINE_ARM64": {"zh": "ARM64 64 位", "en": "ARM64 (64-bit)"},
        "IMAGE_FILE_MACHINE_ARMNT": {"zh": "ARM Thumb-2", "en": "ARM Thumb-2"},
        "IMAGE_FILE_MACHINE_THUMB": {"zh": "ARM Thumb-2", "en": "ARM Thumb-2"},
        "IMAGE_FILE_MACHINE_ALPHA": {"zh": "Alpha", "en": "Alpha"},
        "IMAGE_FILE_MACHINE_MIPS16": {"zh": "MIPS 16 位", "en": "MIPS (16-bit)"},
        "IMAGE_FILE_MACHINE_SH3": {"zh": "SuperH 32 位", "en": "SuperH 32-bit"},
        "IMAGE_FILE_MACHINE_SH3E": {"zh": "SuperH 32 位增强", "en": "SuperH 32-bit (enhanced)"},
        "IMAGE_FILE_MACHINE_SH4": {"zh": "SuperH 64 位", "en": "SuperH 64-bit"},
        "IMAGE_FILE_MACHINE_SH5": {"zh": "SuperH 64 位增强", "en": "SuperH 64-bit (enhanced)"},
        "IMAGE_FILE_MACHINE_RISCV32": {"zh": "RISC-V 32 位", "en": "RISC-V (32-bit)"},
        "IMAGE_FILE_MACHINE_RISCV64": {"zh": "RISC-V 64 位", "en": "RISC-V (64-bit)"},
        "IMAGE_FILE_MACHINE_RISCV128": {"zh": "RISC-V 128 位", "en": "RISC-V (128-bit)"},
        "IMAGE_FILE_MACHINE_LOONGARCH32": {"zh": "龙芯 LoongArch 32 位", "en": "LoongArch (32-bit)"},
        "IMAGE_FILE_MACHINE_LOONGARCH64": {"zh": "龙芯 LoongArch 64 位", "en": "LoongArch (64-bit)"},
        "IMAGE_FILE_MACHINE_UNKNOWN": {"zh": "未知架构", "en": "Unknown architecture"},
    },
    "SUBSYSTEM": {
        "IMAGE_SUBSYSTEM_UNKNOWN": {"zh": "未知子系统", "en": "Unknown subsystem"},
        "IMAGE_SUBSYSTEM_NATIVE": {"zh": "原生内核驱动", "en": "Native (kernel driver)"},
        "IMAGE_SUBSYSTEM_WINDOWS_GUI": {"zh": "Windows 图形界面程序", "en": "Windows GUI"},
        "IMAGE_SUBSYSTEM_WINDOWS_CUI": {"zh": "Windows 控制台程序", "en": "Windows console"},
        "IMAGE_SUBSYSTEM_OS2_CUI": {"zh": "OS/2 控制台程序", "en": "OS/2 console"},
        "IMAGE_SUBSYSTEM_POSIX_CUI": {"zh": "POSIX 控制台程序", "en": "POSIX console"},
        "IMAGE_SUBSYSTEM_NATIVE_WINDOWS": {"zh": "原生 Windows", "en": "Native Windows"},
        "IMAGE_SUBSYSTEM_WINDOWS_CE_GUI": {"zh": "Windows CE 图形界面程序", "en": "Windows CE GUI"},
        "IMAGE_SUBSYSTEM_EFI_APPLICATION": {"zh": "EFI 应用程序", "en": "EFI application"},
        "IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER": {"zh": "EFI 引导服务驱动", "en": "EFI boot-service driver"},
        "IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER": {"zh": "EFI 运行时驱动", "en": "EFI runtime driver"},
        "IMAGE_SUBSYSTEM_EFI_ROM": {"zh": "EFI ROM 映像", "en": "EFI ROM image"},
        "IMAGE_SUBSYSTEM_XBOX": {"zh": "Xbox 游戏机", "en": "Xbox"},
        "IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION": {"zh": "Windows 引导应用程序", "en": "Windows boot application"},
    },
    # A4：调试目录类型。键为 pe_debug._DEBUG_TYPE_NAMES 的规范标准名（如 "CodeView"）
    "DEBUG_TYPE": {
        "Unknown": {"zh": "未知类型", "en": "Unknown"},
        "Coff": {"zh": "COFF 调试信息", "en": "COFF"},
        "CodeView": {"zh": "CodeView 代码视图", "en": "CodeView"},
        "FPO": {"zh": "FPO 帧指针省略", "en": "Frame pointer omission"},
        "Misc": {"zh": "杂项调试信息", "en": "Miscellaneous"},
        "Exception": {"zh": "异常处理调试信息", "en": "Exception"},
        "Fixup": {"zh": "重定位调试信息", "en": "Fixup"},
        "OmapToSrc": {"zh": "OmapToSrc 源映射", "en": "Omap to source"},
        "OmapFromSrc": {"zh": "OmapFromSrc 源映射", "en": "Omap from source"},
        "Borland": {"zh": "Borland 调试信息", "en": "Borland"},
        "Reserved10": {"zh": "保留类型（10）", "en": "Reserved (10)"},
        "CLSID": {"zh": "类标识符（CLSID）", "en": "CLSID"},
        "VCFeature": {"zh": "VC 特性", "en": "VC feature"},
        "POGO": {"zh": "配置文件引导优化", "en": "Profile-guided optimization"},
        "ILTG": {"zh": "增量链接时间戳（ILTG）", "en": "Incremental link time stamp"},
        "MPX": {"zh": "内存保护扩展（MPX）", "en": "Memory protection extensions"},
        "Repro": {"zh": "可复现构建", "en": "Reproducible build"},
        "ExDllCharacteristics": {"zh": "DLL 特性扩展", "en": "Extended DLL characteristics"},
    },
    "RISK_CATEGORY": {
        "进程注入": {"zh": "进程注入", "en": "Process injection"},
        "进程操作": {"zh": "进程操作", "en": "Process operations"},
        "DLL 操作": {"zh": "DLL 操作", "en": "DLL operations"},
        "内存操作": {"zh": "内存操作", "en": "Memory operations"},
        "注册表": {"zh": "注册表", "en": "Registry"},
        "网络": {"zh": "网络", "en": "Network"},
        "文件": {"zh": "文件", "en": "File"},
        "加密": {"zh": "加密", "en": "Cryptography"},
        "反调试": {"zh": "反调试", "en": "Anti-debugging"},
        "键盘记录": {"zh": "键盘记录", "en": "Keylogging"},
        "屏幕截图": {"zh": "屏幕截图", "en": "Screen capture"},
        "自启动": {"zh": "自启动", "en": "Persistence"},
        "信息收集": {"zh": "信息收集", "en": "Information gathering"},
        "凭据窃取": {"zh": "凭据窃取", "en": "Credential theft"},
        "防御规避": {"zh": "防御规避", "en": "Defense evasion"},
        "横向移动": {"zh": "横向移动", "en": "Lateral movement"},
        "系统破坏": {"zh": "系统破坏", "en": "System destruction"},
        "音视频采集": {"zh": "音视频采集", "en": "Audio/video capture"},
        "内核操作": {"zh": "内核操作", "en": "Kernel operations"},
        "内核钩子": {"zh": "内核钩子", "en": "Kernel hooks"},
        "驱动加载": {"zh": "驱动加载", "en": "Driver loading"},
        "网络过滤": {"zh": "网络过滤", "en": "Network filtering"},
    },
    # 预留分类占位（未来按需启用）
    "DLL": {},
}

# 外置翻译文件路径（项目根 assets/ 下，用户可自行编辑扩充，无需改代码）
TRANSLATIONS_PATH = Path(__file__).resolve().parent.parent / "assets" / "translations.json"


def _norm_trans_entry(value) -> dict[str, str]:
    """把外置翻译条目归一化为 {lang: text}。

    - 新格式：{"zh": "...", "en": "..."} → 原样取字符串值
    - 旧格式："中文" → 视为中文（向后兼容）
    - 其它：忽略
    """
    if isinstance(value, dict):
        out: dict[str, str] = {}
        for lang, text in value.items():
            if isinstance(text, str) and text:
                out[str(lang)] = text
        return out
    if isinstance(value, str) and value:
        return {"zh": value}
    return {}


def _load_translations() -> dict[str, dict[str, dict[str, str]]]:
    """从 assets/translations.json 合并到内置翻译表。

    外置的目的：让用户能自行编辑/扩充词条，不必改动 Python 代码。
    加载失败时**记录告警并回退内置**（不再静默 pass），告警会进入
    report.warnings，分析员能明确知道自定义词条未生效。
    合并策略：内置为底，外置按分类覆盖。
    """
    merged: dict[str, dict[str, dict[str, str]]] = {
        cat: {key: dict(val) for key, val in bucket.items()}
        for cat, bucket in _BUILTIN_TRANSLATIONS.items()
    }
    try:
        with TRANSLATIONS_PATH.open(encoding="utf-8") as fh:
            raw = json.load(fh)
    except FileNotFoundError:
        # 外置文件本就是可选项，缺失不告警
        return merged
    except (OSError, json.JSONDecodeError) as exc:
        LOAD_WARNINGS.append(("warn.trans_load_failed", {"err": exc}))
        return merged

    if not isinstance(raw, dict):
        LOAD_WARNINGS.append(("warn.trans_bad_root", {}))
        return merged

    for cat, items in raw.items():
        if not isinstance(items, dict):
            continue
        bucket = merged.setdefault(str(cat), {})
        for key, value in items.items():
            norm = _norm_trans_entry(value)
            if norm:
                bucket.setdefault(str(key), {}).update(norm)
    return merged


# 全局翻译表（模块加载时一次性载入）
TRANSLATIONS: dict[str, dict[str, dict[str, str]]] = _load_translations()


def translate(category: str, key: str, default: str = "", lang: str | None = None) -> str:
    """通用翻译查找：translate("分类", "键", lang="en")。

    查找顺序：指定语言 → 中文 → default。任一步命中即返回。
    """
    if not category or not key:
        return default
    lang = lang or get_language()
    bucket = TRANSLATIONS.get(category)
    if not bucket:
        return default
    entry = bucket.get(key)
    if not entry:
        return default
    return entry.get(lang) or entry.get("zh") or default


def translate_pair(category: str, key: str, lang: str | None = None) -> str:
    """通用「英文标识（说明）」拼接，说明随当前语言变化。

    例：中文 → "IMAGE_FILE_MACHINE_AMD64（x64 64 位）"
        英文 → "IMAGE_FILE_MACHINE_AMD64 (x64 (64-bit))"
    """
    if not key:
        return ""
    lang = lang or get_language()
    text = translate(category, key, lang=lang)
    if not text:
        return key
    left, right = ("（", "）") if lang == "zh" else (" (", ")")
    return f"{key}{left}{text}{right}"


def zh_pair(english: str, chinese: str) -> str:
    """把英文标识与中文说明拼成「英文（中文）」；没有中文时只返回英文。

    保留该函数仅为向后兼容（老代码用鸭子类型调用）；
    新代码请直接用 translate_pair("分类", key, lang=...)。
    """
    english = english or ""
    chinese = chinese or ""
    return f"{english}（{chinese}）" if chinese else english
