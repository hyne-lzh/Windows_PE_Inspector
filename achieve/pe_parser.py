"""PE 解析核心：数据结构 + 纯解析逻辑。

只依赖 pefile 与标准库（数字签名校验在 Windows 上用 ctypes 调系统 API）；
**禁止 import customtkinter / tkinter**。
解析入口 parse_pe() 返回 PeReport，供命令行与图形界面共用（单一真相源）。

能力概览
--------
- 文件头 / 节区（熵值 + 采样）/ 导入表 / 导出表
- 高危 API 匹配（外置 assets/high_risk_apis.json，608 条 / 22 分类）
- DLL 用途说明（外置 assets/dll_meanings.json）
- 打包器识别（UPX / PyInstaller / Nuitka / VMProtect 等）
- 数字签名校验（Windows Authenticode，绝不执行样本）
- 中英双语（文本随当前语言生成，见 achieve/i18n.py）
"""

from __future__ import annotations

import datetime
import json
import math
import re
import struct
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

import pefile

from .i18n import get_language, t
from .strings_extractor import classify_strings, extract_strings

# 节区熵值超过该阈值即提示"疑似加壳/加密"（8.0 为理论上限）
ENTROPY_WARN = 7.2

# 采样熵：节区原始数据超过该阈值时改用采样估算（全量算熵在大文件上很慢）
ENTROPY_SAMPLE_THRESHOLD = 50 * 1024 * 1024   # 50 MB 以上走采样
ENTROPY_SAMPLE_SIZE = 4 * 1024 * 1024          # 采样 4 MB

# 安全上限：超过该大小直接拒绝解析（本工具要面对恶意样本，不能让它耗尽内存）
MAX_FILE_SIZE = 2 * 1024 * 1024 * 1024        # 2 GB

# 打包器特征字符串扫描的字符串条数上限（防超大样本卡顿）
PACKER_SCAN_LIMIT = 20000

# 节区特征位（挑常用的）
SECTION_FLAGS = (
    (0x00000020, "CODE"),
    (0x00000040, "IDATA"),
    (0x00000080, "UDATA"),
    (0x20000000, "X"),
    (0x40000000, "R"),
    (0x80000000, "W"),
)

# --------------------------------------------------------------------------
# 节区属性异常判定（A5：危险节区属性识别）
# --------------------------------------------------------------------------
# 权限位常量（IMAGE_SCN_MEM_*）
SCN_MEM_EXECUTE = 0x20000000
SCN_MEM_READ = 0x40000000
SCN_MEM_WRITE = 0x80000000

# 正常可写的节区名白名单——可写但不在名单内才算可疑，避免系统文件误报。
# 实测依据（扫描 System32 下 400+ DLL / 200 EXE）：
#   - 常见可写节区：.data(386 次) / .didat(232 次) / .mrdata；
#   - RT_BSS / RT_DATA 是 MSVC /RTC 运行时检查段；
#   - .imrsiv 是 MSVC 增量链接（/INCREMENTAL）产生的小节区，系统 EXE 命中 31 次；
#   - 以上均为正常编译产物。其余可写名仅个位数（.fptable / PAGEDATA / cipolicy
#     等属第三方自定义节区），保留为"可疑"是合理预期。
NORMALLY_WRITABLE_SECTIONS = frozenset({
    ".data", ".bss", ".didat", ".mrdata", ".tls", ".idata", ".data1",
    "rt_bss", "rt_data", ".imrsiv",
})

# VirtualSize 超过 RawSize 的倍数阈值。**仅对可执行节区判定**：
# 数据节区（.data 等）常因预留大块未初始化缓冲区而大幅展开——实测 AcLayers.dll
# 的 .data 达 156 倍（正常），故对数据节区判定必然误报；而可执行节区在磁盘上
# 几乎不占空间、内存中却很大，才是典型的"运行时解压出代码"（加壳）特征。
SECTION_EXPAND_RATIO = 5.0

# 合规节区名：字母/数字/下划线/点/连字符/美元符（PE 常见）
_SECTION_NAME_RE = re.compile(r"^[\w.$-]+$")

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
        "IMAGE_FILE_MACHINE_THUMB": {"zh": "ARM Thumb", "en": "ARM Thumb"},
        "IMAGE_FILE_MACHINE_ALPHA": {"zh": "Alpha", "en": "Alpha"},
        "IMAGE_FILE_MACHINE_MIPS16": {"zh": "MIPS 16 位", "en": "MIPS (16-bit)"},
        "IMAGE_FILE_MACHINE_SH3": {"zh": "SuperH 32 位", "en": "SuperH (32-bit)"},
        "IMAGE_FILE_MACHINE_SH3E": {"zh": "SuperH 32 位增强", "en": "SuperH (32-bit, enhanced)"},
        "IMAGE_FILE_MACHINE_SH4": {"zh": "SuperH 64 位", "en": "SuperH (64-bit)"},
        "IMAGE_FILE_MACHINE_SH5": {"zh": "SuperH 64 位增强", "en": "SuperH (64-bit, enhanced)"},
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
        "IMAGE_SUBSYSTEM_WINDOWS_CE_GUI": {"zh": "Windows CE 图形界面", "en": "Windows CE GUI"},
        "IMAGE_SUBSYSTEM_EFI_APPLICATION": {"zh": "EFI 应用程序", "en": "EFI application"},
        "IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER": {"zh": "EFI 引导服务驱动", "en": "EFI boot-service driver"},
        "IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER": {"zh": "EFI 运行时驱动", "en": "EFI runtime driver"},
        "IMAGE_SUBSYSTEM_EFI_ROM": {"zh": "EFI ROM 映像", "en": "EFI ROM image"},
        "IMAGE_SUBSYSTEM_XBOX": {"zh": "Xbox 游戏机", "en": "Xbox"},
        "IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION": {"zh": "Windows 引导应用程序", "en": "Windows boot application"},
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

# 加载期告警：以 (i18n_key, kwargs) 形式记录，避免"静默降级"——见 _load_* 函数。
# 由 _build_report 翻译后并入 report.warnings。
_LOAD_WARNINGS: list[tuple[str, dict]] = []


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
        _LOAD_WARNINGS.append(("warn.trans_load_failed", {"err": exc}))
        return merged

    if not isinstance(raw, dict):
        _LOAD_WARNINGS.append(("warn.trans_bad_root", {}))
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


class PeParseError(Exception):
    """解析失败。message 是面向用户的中文文案；exit_code 供命令行返回。"""

    def __init__(self, message: str, exit_code: int = 1) -> None:
        super().__init__(message)
        self.exit_code = exit_code


@dataclass
class ImportSymbol:
    name: str | None            # 有名导入
    ordinal: int | None         # 序号导入（name 为 None 时使用）

    @property
    def display(self) -> str:
        return self.name or f"Ordinal#{self.ordinal}"


@dataclass
class ImportDLL:
    dll: str
    symbols: list[ImportSymbol] = field(default_factory=list)
    meaning: str = ""           # DLL 用途说明（来自 assets/dll_meanings.json，可能为空）


@dataclass
class ExportSymbol:
    ordinal: int
    rva: int
    name: str | None            # None 表示"(仅序号)"
    forwarder: str | None       # None 表示无转发


@dataclass
class SectionInfo:
    name: str                   # 解码失败或为空 → "(无名)"
    virtual_size: int
    raw_size: int
    entropy: float
    characteristics: int
    perms: str                  # 缩写如 "CODEXR"
    perms_zh: str               # 权限含义（随当前语言，如 "代码·可执行·可读"）
    is_suspicious: bool         # entropy > ENTROPY_WARN
    entropy_sampled: bool = False  # True = 该熵值是采样估算（节区过大，非全量）
    suspicious_reasons: list[str] = field(default_factory=list)  # A5：属性异常原因（随语言）


@dataclass
class RiskyImport:
    """高危 API 导入：分类、风险等级、简要说明。

    注意：``category`` 与 ``risk_level`` 是**数据值**（恒为中文），
    展示层用 translate("RISK_CATEGORY", ...) / i18n t("risk.<等级>") 翻译。
    """
    dll: str
    function: str
    category: str               # 如 "进程注入" / "网络"（数据值，不翻译）
    risk_level: str             # "严重" / "中等" / "低"（数据值，不翻译）
    description: str            # 中文说明


@dataclass
class PackerHit:
    """命中的打包器特征。``name`` 是品牌名（不翻译），证据分节区与字符串两类。"""
    name: str
    sections: list[str] = field(default_factory=list)   # 命中的节区名
    strings: list[str] = field(default_factory=list)     # 命中的特征字符串


# 签名状态取值
SIG_NONE = "none"
SIG_VALID = "valid"
SIG_INVALID = "invalid"
SIG_UNKNOWN = "unknown"


@dataclass
class SignatureInfo:
    """数字签名信息。status 取值见 SIG_* 常量。"""
    present: bool = False
    status: str = SIG_NONE
    signer: str = ""
    issuer: str = ""
    detail: str = ""            # 失败原因 / 错误码
    size: int = 0               # 签名数据大小（字节）


@dataclass
class PeReport:
    path: str
    file_size: int
    magic: int
    kind: str
    bits: int
    machine: int
    machine_name: str
    machine_zh: str              # 架构说明（随当前语言）
    subsystem: int
    subsystem_name: str
    subsystem_zh: str            # 子系统说明（随当前语言）
    time_date_stamp: int
    compile_time_text: str
    time_in_future: bool
    entry_point_rva: int
    image_base: int
    checksum: int
    num_sections: int
    num_data_directories: int
    sections: list[SectionInfo] = field(default_factory=list)
    imports: list[ImportDLL] = field(default_factory=list)
    exports: list[ExportSymbol] = field(default_factory=list)
    risky_imports: list[RiskyImport] = field(default_factory=list)
    strings_summary: dict = field(default_factory=dict)  # extract_strings 完整结果（含来源/失败原因）
    string_count: int = 0                                # 合并去重后的字符串总数
    string_classes: dict = field(default_factory=dict)   # classify_strings 分类结果
    packers: list[PackerHit] = field(default_factory=list)  # 命中的打包器特征
    signature: SignatureInfo = field(default_factory=SignatureInfo)  # 数字签名
    has_imports: bool = False
    has_exports: bool = False
    has_risky_imports: bool = False
    has_packers: bool = False
    suspicious_sections: bool = False
    suspicious_section_count: int = 0   # A5：属性异常的节区个数
    lang: str = "zh"             # 生成本报告时使用的语言
    warnings: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------
# 纯格式工具
# --------------------------------------------------------------------------

def human_size(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    if n < 1024 * 1024 * 1024:
        return f"{n / 1024 / 1024:.1f} MB"
    return f"{n / 1024 / 1024 / 1024:.2f} GB"


def _is_future(stamp: int) -> bool:
    """判断时间戳是否晚于当前时间（含同年内未来日期，不只看年份）。"""
    if not stamp:
        return False
    try:
        dt = datetime.datetime.fromtimestamp(stamp, tz=datetime.timezone.utc)
    except (OverflowError, OSError, ValueError):
        return False
    return dt > datetime.datetime.now(datetime.timezone.utc)


def fmt_time(stamp: int, lang: str | None = None) -> str:
    lang = lang or get_language()
    if not stamp:
        return t("time.unset", lang=lang)
    try:
        dt = datetime.datetime.fromtimestamp(stamp, tz=datetime.timezone.utc)
    except (OverflowError, OSError, ValueError):
        return t("time.invalid", lang=lang, stamp=stamp)
    text = dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    if _is_future(stamp):
        text += t("time.future_suffix", lang=lang)
    return text


def section_perms(ch: int) -> str:
    return "".join(name for bit, name in SECTION_FLAGS if ch & bit) or "-"


def perms_to_zh(perms: str, lang: str | None = None) -> str:
    """把权限缩写翻译为含义文本，例如 "CODEXR" → "代码·可执行·可读"。

    按最长优先匹配多字符代码（UDATA 5 > IDATA 5 > CODE 4 > X/R/W 1）。
    翻译走通用 translate("SECTION_FLAGS", code, lang=lang)。
    """
    if not perms or perms == "-":
        return "-"
    lang = lang or get_language()
    bucket = TRANSLATIONS.get("SECTION_FLAGS", {})
    # 按字符长度从长到短排序（UDATA/IDATA 5 > CODE 4 > X/R/W 1），保证贪婪匹配
    codes_by_len = sorted(bucket.keys(), key=len, reverse=True)
    parts: list[str] = []
    remaining = perms
    while remaining:
        matched = False
        for code in codes_by_len:
            if remaining.startswith(code):
                parts.append(translate("SECTION_FLAGS", code, default=code, lang=lang))
                remaining = remaining[len(code):]
                matched = True
                break
        if not matched:
            # 理论上不会发生（section_perms 只产出已知代码），但兜底保留单字符
            parts.append(remaining[0])
            remaining = remaining[1:]
    return "·".join(parts)


def check_section_anomaly(name: str, characteristics: int,
                          virtual_size: int, raw_size: int,
                          lang: str | None = None) -> list[str]:
    """判定单个节区的属性异常，返回可疑原因列表（空列表 = 正常）。

    规则（A5）：
      1. 可写且可执行（W+X）        —— 自修改代码 / 加壳释放代码的典型特征；
      2. 可写但节区名不在正常白名单 —— 该节区本不该可写；
      3. 节区名为空或含非常规字符    —— 可能被篡改；
      4. VirtualSize > RawSize × 5  —— 内存展开远大于磁盘大小，加壳特征。

    ``name`` 传**原始**节区名（未做 "(无名)" 兜底），以便识别空名。
    文案随 ``lang``，与 ``perms_zh`` 的做法一致。
    """
    lang = lang or get_language()
    reasons: list[str] = []

    writable = bool(characteristics & SCN_MEM_WRITE)
    executable = bool(characteristics & SCN_MEM_EXECUTE)
    lower = (name or "").lower()

    # 规则 1：W+X
    if writable and executable:
        reasons.append(t("section.suspect_wx", lang=lang))

    # 规则 2：可写且不在白名单（规则 1 已报过就不重复）
    if writable and not executable and lower not in NORMALLY_WRITABLE_SECTIONS:
        reasons.append(t("section.suspect_writable", lang=lang))

    # 规则 3：节区名为空或非常规字符
    if not name or not _SECTION_NAME_RE.match(name):
        reasons.append(t("section.suspect_name", lang=lang))

    # 规则 4：可执行节区内存展开远大于磁盘大小（加壳特征）
    # raw_size 为 0 时不判（避免除零，也避免把纯 .bss 类节区误报）
    if executable and raw_size > 0 and virtual_size > raw_size * SECTION_EXPAND_RATIO:
        reasons.append(t("section.suspect_expand", lang=lang))

    return reasons


# 兼容旧引用（内部私有别名，新代码请用 check_section_anomaly）
_check_section_anomaly = check_section_anomaly


# --------------------------------------------------------------------------
# 采样熵（性能：超大节区不再全量计算）
# --------------------------------------------------------------------------

def _entropy_of(data: bytes) -> float:
    """计算字节序列的香农熵（0~8）。与 pefile 的 get_entropy() 算法一致。"""
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    ent = 0.0
    for c in counts.values():
        p = c / total
        ent -= p * math.log2(p)
    return ent


def _sampled_data(data: bytes, sample_size: int) -> bytes:
    """从大块数据里采样：取头、中、尾三段各 sample_size/3，兼顾代表性与速度。"""
    if len(data) <= sample_size:
        return data
    third = max(1, sample_size // 3)
    head = data[:third]
    mid_start = (len(data) - third) // 2
    mid = data[mid_start:mid_start + third]
    tail = data[-third:]
    return head + mid + tail


def section_entropy(section, sample_threshold: int = ENTROPY_SAMPLE_THRESHOLD) -> tuple[float, bool]:
    """计算节区熵值，返回 (熵值, 是否采样)。

    - 节区数据 <= sample_threshold（默认 50 MB）：全量计算，结果精确
    - 超过阈值：改用 4 MB 采样估算，避免大文件上几十秒的卡顿
    """
    try:
        data = section.get_data()
    except Exception:  # noqa: BLE001
        # get_data 可能失败（如 SizeOfRawData 为 0），回退到 pefile 自带实现
        try:
            return float(section.get_entropy()), False
        except Exception:  # noqa: BLE001
            return 0.0, False

    if len(data) > sample_threshold:
        return _entropy_of(_sampled_data(data, ENTROPY_SAMPLE_SIZE)), True
    return _entropy_of(data), False


# --------------------------------------------------------------------------
# 高危 API 词典（key 用小写，匹配时统一小写化）
# 值：(分类, 风险等级, 说明)
# --------------------------------------------------------------------------

# 内置兜底词典（仅在 assets/high_risk_apis.json 缺失/损坏时启用）
_BUILTIN_HIGH_RISK_APIS: dict[str, tuple[str, str, str]] = {
    # ---- 进程注入（严重）----
    "createremotethread":    ("进程注入", "严重", "在远程进程中创建线程，常用于代码注入"),
    "ntcreatethreadex":      ("进程注入", "严重", "原生层创建远程线程"),
    "virtualallocex":        ("进程注入", "严重", "在远程进程中分配内存"),
    "writeprocessmemory":    ("进程注入", "严重", "写入远程进程内存"),
    "readprocessmemory":     ("进程注入", "严重", "读取远程进程内存"),
    "openprocess":           ("进程注入", "中等", "打开远程进程句柄"),

    # ---- 进程操作 ----
    "terminateprocess":      ("进程操作", "中等", "终止指定进程"),
    "createprocessa":        ("进程操作", "低",   "创建新进程（ANSI）"),
    "createprocessw":        ("进程操作", "低",   "创建新进程（Unicode）"),
    "shellexecutea":         ("进程操作", "低",   "执行外部命令（ANSI）"),
    "shellexecutew":         ("进程操作", "低",   "执行外部命令（Unicode）"),
    "winexec":               ("进程操作", "低",   "执行外部命令"),
    "createprocessasusera":  ("进程操作", "中等", "以其他用户身份创建进程"),
    "createprocessasuserw":  ("进程操作", "中等", "以其他用户身份创建进程"),

    # ---- DLL 操作 ----
    "loadlibrarya":          ("DLL 操作", "中等", "动态加载 DLL（ANSI）"),
    "loadlibraryw":          ("DLL 操作", "中等", "动态加载 DLL（Unicode）"),
    "loadlibraryexa":        ("DLL 操作", "中等", "从指定路径加载 DLL（ANSI）"),
    "loadlibraryexw":        ("DLL 操作", "中等", "从指定路径加载 DLL（Unicode）"),
    "getprocaddress":        ("DLL 操作", "中等", "获取 DLL 函数地址"),
    "getmodulehandlea":      ("DLL 操作", "低",   "获取模块句柄（ANSI）"),
    "getmodulehandlew":      ("DLL 操作", "低",   "获取模块句柄（Unicode）"),
    "ldrloaddll":            ("DLL 操作", "中等", "原生层加载 DLL"),
    "freelibrary":           ("DLL 操作", "低",   "释放 DLL"),
    "freelibraryandexitthread": ("DLL 操作", "严重", "释放 DLL 并退出线程，常用于注入后退出宿主"),

    # ---- 内存操作 ----
    "virtualprotect":        ("内存操作", "中等", "修改内存页面保护属性"),
    "virtualprotectex":      ("内存操作", "中等", "修改远程进程内存保护属性"),
    "virtualalloc":          ("内存操作", "低",   "分配虚拟内存"),
    "virtualfree":           ("内存操作", "低",   "释放虚拟内存"),
    "virtualquery":          ("内存操作", "低",   "查询虚拟内存信息"),
    "heapcreate":            ("内存操作", "低",   "创建堆"),
    "heapalloc":             ("内存操作", "低",   "堆内存分配"),
    "virtualqueryex":        ("内存操作", "低",   "查询远程进程虚拟内存"),

    # ---- 注册表 ----
    "regsetvalueexa":        ("注册表",   "中等", "设置注册表值（ANSI）"),
    "regsetvalueexw":        ("注册表",   "中等", "设置注册表值（Unicode），常用于自启动"),
    "regcreatekeyexa":       ("注册表",   "中等", "创建注册表键（ANSI）"),
    "regcreatekeyexw":       ("注册表",   "中等", "创建注册表键（Unicode）"),
    "regdeletekeya":         ("注册表",   "中等", "删除注册表键（ANSI）"),
    "regdeletekeyw":         ("注册表",   "中等", "删除注册表键（Unicode）"),
    "regdeletevaluea":       ("注册表",   "中等", "删除注册表值（ANSI）"),
    "regdeletevaluew":       ("注册表",   "中等", "删除注册表值（Unicode）"),
    "regopenkeyexa":         ("注册表",   "低",   "打开注册表键（ANSI）"),
    "regopenkeyexw":         ("注册表",   "低",   "打开注册表键（Unicode）"),
    "regenumkeyexa":         ("注册表",   "低",   "枚举注册表子键（Unicode）"),

    # ---- 网络 ----
    "wsastartup":            ("网络",     "中等", "初始化 Winsock"),
    "socket":                ("网络",     "中等", "创建套接字"),
    "connect":               ("网络",     "中等", "连接远程地址"),
    "send":                  ("网络",     "中等", "发送数据"),
    "recv":                  ("网络",     "中等", "接收数据"),
    "internetopena":         ("网络",     "中等", "初始化 WinINet（ANSI）"),
    "internetopenw":         ("网络",     "中等", "初始化 WinINet（Unicode）"),
    "internetconnecta":      ("网络",     "中等", "连接服务器（ANSI）"),
    "internetconnectw":      ("网络",     "中等", "连接服务器（Unicode）"),
    "httpsendrequesta":      ("网络",     "中等", "发送 HTTP 请求（ANSI）"),
    "httpsendrequestw":      ("网络",     "中等", "发送 HTTP 请求（Unicode）"),
    "urldownloadtofilea":    ("网络",     "严重", "下载文件到本地（ANSI），常用于木马下载"),
    "urldownloadtofilew":    ("网络",     "严重", "下载文件到本地（Unicode），常用于木马下载"),
    "inetntoa":              ("网络",     "低",   "IP 地址转字符串"),
    "gethostbyname":         ("网络",     "中等", "域名解析为 IP"),
    "dnsquery":              ("网络",     "中等", "DNS 查询"),
    "sendto":                ("网络",     "中等", "UDP 发送数据"),

    # ---- 文件 ----
    "createfilea":           ("文件",     "低",   "创建/打开文件（ANSI）"),
    "createfilew":           ("文件",     "低",   "创建/打开文件（Unicode）"),
    "writefile":             ("文件",     "低",   "写入文件"),
    "readfile":              ("文件",     "低",   "读取文件"),
    "deletefilea":           ("文件",     "中等", "删除文件（ANSI）"),
    "deletefilew":           ("文件",     "中等", "删除文件（Unicode）"),
    "movefilea":             ("文件",     "低",   "移动文件（ANSI）"),
    "movefilew":             ("文件",     "低",   "移动文件（Unicode）"),
    "copyfilea":             ("文件",     "低",   "复制文件（ANSI）"),
    "copyfilew":             ("文件",     "低",   "复制文件（Unicode）"),
    "createprocessinternala": ("文件",    "中等", "原生层创建进程（ANSI）"),
    "createprocessinternalw": ("文件",    "中等", "原生层创建进程（Unicode）"),

    # ---- 加密 ----
    "cryptacquirecontexta":  ("加密",     "低",   "获取加密上下文（ANSI）"),
    "cryptacquirecontextw":  ("加密",     "低",   "获取加密上下文（Unicode）"),
    "cryptgenrandom":        ("加密",     "低",   "生成随机数"),
    "cryptencrypt":          ("加密",     "低",   "加密数据"),
    "cryptdecrypt":          ("加密",     "低",   "解密数据"),
    "crypthashdata":         ("加密",     "低",   "计算哈希"),

    # ---- 反调试（严重）----
    "isdebuggerpresent":            ("反调试", "严重", "检测当前进程是否被调试"),
    "checkremotedebuggerpresent":   ("反调试", "严重", "检测远程调试器"),
    "ntqueryinformationprocess":    ("反调试", "中等", "查询进程信息，常用于反调试"),
    "queryperformancecounter":      ("反调试", "中等", "性能计数器，常用于反调试时间检测"),
    "gettickcount":                 ("反调试", "低",   "获取系统启动毫秒数"),
    "ntquerysysteminformation":     ("反调试", "中等", "查询系统信息"),
    "rtladjustprivilege":           ("反调试", "严重", "提权操作"),
    "ntsetinformationprocess":      ("反调试", "严重", "设置进程信息"),
    "zwqueryinformationprocess":    ("反调试", "中等", "原生层查询进程信息"),
    "findwindowa":                  ("反调试", "中等", "查找窗口（ANSI），常用于检测调试器窗口"),
    "findwindoww":                  ("反调试", "中等", "查找窗口（Unicode）"),

    # ---- 键盘记录（严重）----
    "setwindowshookexa":            ("键盘记录", "严重", "设置全局钩子（ANSI），常用于键盘记录"),
    "setwindowshookexw":            ("键盘记录", "严重", "设置全局钩子（Unicode），常用于键盘记录"),
    "getasynckeystate":             ("键盘记录", "严重", "获取异步按键状态，常用于键盘记录"),
    "getkeystate":                  ("键盘记录", "中等", "获取按键状态"),
    "registerhotkey":               ("键盘记录", "中等", "注册全局热键"),

    # ---- 屏幕截图 ----
    "bitblt":                       ("屏幕截图", "中等", "位图复制，可用于屏幕截图"),
    "createcompatiblebitmap":       ("屏幕截图", "中等", "创建兼容位图"),
    "getdesktopwindow":             ("屏幕截图", "低",   "获取桌面窗口句柄"),
    "getdc":                        ("屏幕截图", "低",   "获取设备上下文"),
    "getwindowdc":                  ("屏幕截图", "低",   "获取窗口设备上下文"),
    "keybd_event":                  ("屏幕截图", "中等", "模拟键盘事件"),
    "mouse_event":                  ("屏幕截图", "中等", "模拟鼠标事件"),
    "printwindow":                  ("屏幕截图", "中等", "打印窗口内容，可用于截图"),

    # ---- 自启动 / 持久化 ----
    "createtoolhelp32snapshot":     ("自启动",   "中等", "创建进程快照，用于枚举进程"),
    "adjusttokenprivileges":        ("自启动",   "严重", "调整令牌权限，常用于提权"),
    "createservicea":               ("自启动",   "严重", "创建系统服务（ANSI），常用于持久化"),
    "createservicew":               ("自启动",   "严重", "创建系统服务（Unicode），常用于持久化"),
    "openscmanagera":               ("自启动",   "中等", "打开服务控制管理器（ANSI）"),
    "openscmanagerw":               ("自启动",   "中等", "打开服务控制管理器（Unicode）"),
    "startservicea":                ("自启动",   "中等", "启动系统服务（ANSI）"),
    "startservicew":                ("自启动",   "中等", "启动系统服务（Unicode）"),
    "createprocesswithlogonw":      ("自启动",   "中等", "使用其他凭据创建进程"),
}


# 外置词典路径（项目根 assets/ 下，用户可自行编辑扩充，无需改代码）
RISK_DICT_PATH = Path(__file__).resolve().parent.parent / "assets" / "high_risk_apis.json"


def _load_high_risk_apis() -> dict[str, tuple[str, str, str]]:
    """从 assets/high_risk_apis.json 加载高危 API 词典。

    加载失败时**记录告警并回退内置**（不再静默 pass）。
    """
    try:
        with RISK_DICT_PATH.open(encoding="utf-8") as fh:
            raw = json.load(fh)
    except FileNotFoundError:
        return dict(_BUILTIN_HIGH_RISK_APIS)
    except (OSError, json.JSONDecodeError) as exc:
        _LOAD_WARNINGS.append(("warn.risk_load_failed", {"err": exc}))
        return dict(_BUILTIN_HIGH_RISK_APIS)

    loaded: dict[str, tuple[str, str, str]] = {}
    if isinstance(raw, dict):
        for key, val in raw.items():
            if isinstance(val, (list, tuple)) and len(val) == 3:
                loaded[str(key).lower()] = (str(val[0]), str(val[1]), str(val[2]))
    if loaded:
        return loaded
    return dict(_BUILTIN_HIGH_RISK_APIS)


# 实际生效的词典（外部 JSON 优先，内置条目兜底）
HIGH_RISK_APIS: dict[str, tuple[str, str, str]] = _load_high_risk_apis()


# --------------------------------------------------------------------------
# DLL 用途说明词典
# --------------------------------------------------------------------------

DLL_MEANINGS_PATH = Path(__file__).resolve().parent.parent / "assets" / "dll_meanings.json"

# 内置为空（说明性数据纯外置）；加载失败时仅记录告警
_BUILTIN_DLL_MEANINGS: dict[str, str] = {}


def _load_dll_meanings() -> dict[str, str]:
    """从 assets/dll_meanings.json 加载 DLL 用途说明词典（key 统一小写）。"""
    try:
        with DLL_MEANINGS_PATH.open(encoding="utf-8") as fh:
            raw = json.load(fh)
    except FileNotFoundError:
        return dict(_BUILTIN_DLL_MEANINGS)
    except (OSError, json.JSONDecodeError) as exc:
        _LOAD_WARNINGS.append(("warn.dll_load_failed", {"err": exc}))
        return dict(_BUILTIN_DLL_MEANINGS)

    if not isinstance(raw, dict):
        _LOAD_WARNINGS.append(("warn.dll_bad_root", {}))
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


def _scan_risky_imports(imports: list[ImportDLL]) -> list[RiskyImport]:
    """扫描导入表，匹配高危 API 词典。"""
    risky: list[RiskyImport] = []
    for dll in imports:
        for sym in dll.symbols:
            name = sym.display
            key = name.lower()
            if key in HIGH_RISK_APIS:
                category, risk_level, description = HIGH_RISK_APIS[key]
                risky.append(RiskyImport(
                    dll=dll.dll,
                    function=name,
                    category=category,
                    risk_level=risk_level,
                    description=description,
                ))
    return risky


# --------------------------------------------------------------------------
# 打包器识别
# --------------------------------------------------------------------------

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
    """根据节区名与特征字符串识别打包器。

    - 节区名：全等或前缀匹配（如 ``.vmp0``）
    - 字符串：子串匹配；只扫描前 PACKER_SCAN_LIMIT 条，避免超大样本卡顿
    """
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


# --------------------------------------------------------------------------
# 数字签名校验（Windows Authenticode）
# --------------------------------------------------------------------------

def _security_dir_range(pe) -> tuple[int, int]:
    """返回签名目录的 (文件偏移, 大小)；无签名返回 (0, 0)。

    注意：IMAGE_DIRECTORY_ENTRY_SECURITY 的 VirtualAddress 是**文件偏移**而非 RVA。
    """
    try:
        idx = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
        dd = pe.OPTIONAL_HEADER.DATA_DIRECTORY[idx]
        offset, size = int(dd.VirtualAddress), int(dd.Size)
        if offset > 0 and size > 0:
            return offset, size
    except (AttributeError, IndexError, KeyError, TypeError, ValueError):
        pass
    return 0, 0


def _read_signature_blob(pe, path: str, offset: int, size: int) -> bytes | None:
    """读取 PKCS#7 签名数据（跳过 8 字节 WIN_CERTIFICATE 头）。失败返回 None。"""
    raw: bytes | None = None
    try:
        data = getattr(pe, "__data__", None)
        if isinstance(data, (bytes, bytearray)) and offset + 8 <= len(data):
            raw = bytes(data[offset:offset + size])
    except (TypeError, ValueError):
        raw = None
    if raw is None:
        try:
            with open(path, "rb") as fh:
                fh.seek(offset)
                raw = fh.read(size)
        except (OSError, ValueError):
            return None
    if not raw or len(raw) < 8:
        return None
    try:
        length, _revision, _ctype = struct.unpack_from("<IHH", raw, 0)
    except struct.error:
        return None
    if length < 8 or length > len(raw):
        length = len(raw)
    blob = raw[8:length]
    return blob or None


def _win_verify_file(path: str) -> tuple[str, str]:
    """用 Windows WinVerifyTrust 校验文件签名，返回 (status, detail)。

    - status: SIG_VALID / SIG_INVALID / SIG_UNKNOWN
    - detail: 附加说明（错误码等）

    本函数只**读取**文件做密码学校验，绝不加载或执行样本；
    强制 `WTD_CACHE_ONLY_URL_RETRIEVAL`，不联网取 CRL/OCSP。
    """
    try:
        import ctypes
        from ctypes import wintypes
    except Exception as exc:  # noqa: BLE001
        return SIG_UNKNOWN, f"ctypes 不可用：{exc}"

    if not hasattr(ctypes, "windll"):
        return SIG_UNKNOWN, "非 Windows 环境"

    class _GUID(ctypes.Structure):
        _fields_ = [
            ("Data1", wintypes.DWORD),
            ("Data2", wintypes.WORD),
            ("Data3", wintypes.WORD),
            ("Data4", ctypes.c_ubyte * 8),
        ]

    class _WINTRUST_FILE_INFO(ctypes.Structure):
        _fields_ = [
            ("cbStruct", wintypes.DWORD),
            ("pcwszFilePath", wintypes.LPCWSTR),
            ("hFile", wintypes.HANDLE),
            ("pgKnownSubject", ctypes.POINTER(_GUID)),
        ]

    class _WINTRUST_DATA(ctypes.Structure):
        _fields_ = [
            ("cbStruct", wintypes.DWORD),
            ("pPolicyCallbackData", ctypes.c_void_p),
            ("pSIPClientData", ctypes.c_void_p),
            ("dwUIChoice", wintypes.DWORD),
            ("fdwRevocationChecks", wintypes.DWORD),
            ("dwUnionChoice", wintypes.DWORD),
            ("pFile", ctypes.POINTER(_WINTRUST_FILE_INFO)),
            ("dwStateAction", wintypes.DWORD),
            ("hWVTStateData", wintypes.HANDLE),
            ("pwszURLReference", wintypes.LPWSTR),
            ("dwProvFlags", wintypes.DWORD),
            ("dwUIContext", wintypes.DWORD),
            ("pSignatureSettings", ctypes.c_void_p),
        ]

    wtd_ui_none = 2
    wtd_revoke_none = 0
    wtd_choice_file = 1
    wtd_state_verify = 1
    wtd_state_close = 2
    wtd_cache_only = 0x00001000   # 仅用本地缓存，避免联网

    action = _GUID(0x00AAC56B, 0xCD44, 0x11D0,
                   (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE))

    file_info = _WINTRUST_FILE_INFO()
    file_info.cbStruct = ctypes.sizeof(_WINTRUST_FILE_INFO)
    file_info.pcwszFilePath = str(path)
    file_info.hFile = None
    file_info.pgKnownSubject = None

    data = _WINTRUST_DATA()
    data.cbStruct = ctypes.sizeof(_WINTRUST_DATA)
    data.pPolicyCallbackData = None
    data.pSIPClientData = None
    data.dwUIChoice = wtd_ui_none
    data.fdwRevocationChecks = wtd_revoke_none
    data.dwUnionChoice = wtd_choice_file
    data.pFile = ctypes.pointer(file_info)
    data.dwStateAction = wtd_state_verify
    data.hWVTStateData = None
    data.pwszURLReference = None
    data.dwProvFlags = wtd_cache_only
    data.dwUIContext = 0
    data.pSignatureSettings = None

    try:
        wintrust = ctypes.WinDLL("wintrust.dll")
        fn = wintrust.WinVerifyTrust
        fn.argtypes = [wintypes.HWND, ctypes.POINTER(_GUID), ctypes.c_void_p]
        fn.restype = ctypes.c_long
    except (OSError, AttributeError) as exc:
        return SIG_UNKNOWN, f"无法加载 wintrust.dll：{exc}"

    try:
        result = fn(None, ctypes.byref(action), ctypes.byref(data))
    except Exception as exc:  # noqa: BLE001
        return SIG_UNKNOWN, f"WinVerifyTrust 调用失败：{exc}"
    finally:
        # 释放校验状态数据，避免句柄泄漏
        try:
            data.dwStateAction = wtd_state_close
            fn(None, ctypes.byref(action), ctypes.byref(data))
        except Exception:  # noqa: BLE001
            pass

    code = int(ctypes.c_long(result).value)
    if code == 0:
        return SIG_VALID, ""
    return SIG_INVALID, f"0x{code & 0xFFFFFFFF:08X}"


def _win_extract_signer(sig_bytes: bytes) -> tuple[str, str]:
    """从 PKCS#7 签名数据中提取 (签名者, 颁发者) 的显示名。失败返回空串。

    用 CryptQueryObject 解析签名，枚举证书取显示名（签名者证书通常排在最前）。
    """
    if not sig_bytes:
        return "", ""
    try:
        import ctypes
        from ctypes import wintypes
    except Exception:  # noqa: BLE001
        return "", ""
    if not hasattr(ctypes, "windll"):
        return "", ""

    class _CRYPT_DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD),
                    ("pbData", ctypes.POINTER(ctypes.c_ubyte))]

    class _CRYPT_ALGORITHM_IDENTIFIER(ctypes.Structure):
        _fields_ = [("pszObjId", ctypes.c_char_p),
                    ("Parameters", _CRYPT_DATA_BLOB)]

    class _FILETIME(ctypes.Structure):
        _fields_ = [("dwLowDateTime", wintypes.DWORD),
                    ("dwHighDateTime", wintypes.DWORD)]

    class _CMSG_SIGNER_INFO(ctypes.Structure):
        # 只声明到 SerialNumber（后续字段 CertFindCertificateInStore 用不到）
        _fields_ = [("dwVersion", wintypes.DWORD),
                    ("Issuer", _CRYPT_DATA_BLOB),
                    ("SerialNumber", _CRYPT_DATA_BLOB)]

    class _CERT_INFO(ctypes.Structure):
        # 部分布局：CertFindCertificateInStore(CERT_FIND_SUBJECT_CERT) 只用 Issuer + SerialNumber
        _fields_ = [("dwVersion", wintypes.DWORD),
                    ("SerialNumber", _CRYPT_DATA_BLOB),
                    ("SignatureAlgorithm", _CRYPT_ALGORITHM_IDENTIFIER),
                    ("Issuer", _CRYPT_DATA_BLOB),
                    ("NotBefore", _FILETIME),
                    ("NotAfter", _FILETIME),
                    ("Subject", _CRYPT_DATA_BLOB)]

    cert_query_object_blob = 2
    cert_query_content_flag_all = 0x3FFE
    cert_query_format_flag_all = 0x0000000E
    cert_name_simple_display_type = 4

    buf = (ctypes.c_ubyte * len(sig_bytes)).from_buffer_copy(sig_bytes)
    blob = _CRYPT_DATA_BLOB(len(sig_bytes), ctypes.cast(buf, ctypes.POINTER(ctypes.c_ubyte)))

    try:
        crypt32 = ctypes.WinDLL("crypt32.dll")
    except OSError:
        return "", ""

    CryptQueryObject = crypt32.CryptQueryObject
    CryptQueryObject.argtypes = [
        wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.HANDLE),
        ctypes.POINTER(wintypes.HANDLE), ctypes.POINTER(ctypes.c_void_p),
    ]
    CryptQueryObject.restype = wintypes.BOOL

    encoding = wintypes.DWORD()
    content_type = wintypes.DWORD()
    format_type = wintypes.DWORD()
    h_store = wintypes.HANDLE()
    h_msg = wintypes.HANDLE()
    p_context = ctypes.c_void_p()

    ok = CryptQueryObject(
        cert_query_object_blob, ctypes.byref(blob),
        cert_query_content_flag_all, cert_query_format_flag_all, 0,
        ctypes.byref(encoding), ctypes.byref(content_type), ctypes.byref(format_type),
        ctypes.byref(h_store), ctypes.byref(h_msg), ctypes.byref(p_context),
    )
    if not ok or not h_store:
        return "", ""

    signer, issuer = "", ""
    try:
        CertGetNameStringW = crypt32.CertGetNameStringW
        CertGetNameStringW.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
                                       ctypes.c_void_p, wintypes.LPWSTR, wintypes.DWORD]
        CertGetNameStringW.restype = wintypes.DWORD

        def _cert_name(cert_ctx, issuer_flag: int = 0) -> str:
            """取证书显示名；issuer_flag=1 时取颁发者名（CERT_NAME_ISSUER_FLAG）。"""
            need = CertGetNameStringW(cert_ctx, cert_name_simple_display_type,
                                      issuer_flag, None, None, 0)
            if need <= 1:
                return ""
            name_buf = ctypes.create_unicode_buffer(need)
            CertGetNameStringW(cert_ctx, cert_name_simple_display_type,
                               issuer_flag, None, name_buf, need)
            return name_buf.value or ""

        # 优先用 CMSG_SIGNER_INFO 精确定位"叶证书"（签名者），避免取到中间 CA
        leaf_ctx = None
        if h_msg:
            try:
                CryptMsgGetParam = crypt32.CryptMsgGetParam
                CryptMsgGetParam.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD,
                                             ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD)]
                CryptMsgGetParam.restype = wintypes.BOOL
                cmsg_signer_info_param = 6
                need_size = wintypes.DWORD()
                if (CryptMsgGetParam(h_msg, cmsg_signer_info_param, 0, None, ctypes.byref(need_size))
                        and need_size.value):
                    info_buf = (ctypes.c_ubyte * need_size.value)()
                    if CryptMsgGetParam(h_msg, cmsg_signer_info_param, 0, info_buf,
                                        ctypes.byref(need_size)):
                        signer_info = _CMSG_SIGNER_INFO.from_buffer(info_buf)
                        cert_info = _CERT_INFO()
                        cert_info.dwVersion = 0
                        cert_info.SerialNumber = signer_info.SerialNumber
                        cert_info.Issuer = signer_info.Issuer
                        CertFindCertificateInStore = crypt32.CertFindCertificateInStore
                        CertFindCertificateInStore.argtypes = [wintypes.HANDLE, wintypes.DWORD,
                                                               wintypes.DWORD, wintypes.DWORD,
                                                               ctypes.c_void_p, ctypes.c_void_p]
                        CertFindCertificateInStore.restype = ctypes.c_void_p
                        x509_pkcs7 = 0x00010001          # X509_ASN_ENCODING | PKCS_7_ASN_ENCODING
                        cert_find_subject_cert = 0x000B0000
                        leaf_ctx = CertFindCertificateInStore(
                            h_store, x509_pkcs7, 0, cert_find_subject_cert,
                            ctypes.byref(cert_info), None)
            except Exception:  # noqa: BLE001
                leaf_ctx = None

        cert_name_issuer_flag = 0x1
        if leaf_ctx:
            signer = _cert_name(leaf_ctx, 0)
            issuer = _cert_name(leaf_ctx, cert_name_issuer_flag)
        if not signer:
            # 回退：枚举证书存储，取第一个作为签名者
            CertEnumCertificatesInStore = crypt32.CertEnumCertificatesInStore
            CertEnumCertificatesInStore.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
            CertEnumCertificatesInStore.restype = ctypes.c_void_p
            cert = CertEnumCertificatesInStore(h_store, None)
            count = 0
            while cert and count < 6:
                name = _cert_name(cert, 0)
                if name and not signer:
                    signer = name
                elif name and not issuer:
                    issuer = name
                cert = CertEnumCertificatesInStore(h_store, cert)
                count += 1
    except Exception:  # noqa: BLE001
        pass
    finally:
        try:
            crypt32.CertCloseStore(h_store, 0)
        except Exception:  # noqa: BLE001
            pass
        if h_msg:
            try:
                crypt32.CryptMsgClose(h_msg)
            except Exception:  # noqa: BLE001
                pass
    return signer, issuer


def check_signature(pe, path: str) -> SignatureInfo:
    """检查 PE 数字签名。无签名 → present=False；有签名 → 校验有效性并提取签名者。"""
    offset, size = _security_dir_range(pe)
    if not offset or not size:
        return SignatureInfo(present=False, status=SIG_NONE)

    info = SignatureInfo(present=True, status=SIG_UNKNOWN, size=size)
    status, detail = _win_verify_file(str(path))
    info.status = status
    info.detail = detail

    blob = _read_signature_blob(pe, str(path), offset, size)
    if blob:
        signer, issuer = _win_extract_signer(blob)
        info.signer = signer
        info.issuer = issuer
    return info


# --------------------------------------------------------------------------
# 解析
# --------------------------------------------------------------------------

def parse_pe(path, lang: str | None = None) -> PeReport:
    """解析 PE 文件，失败时抛 PeParseError（含中文文案与退出码）。

    安全约束（审查项，不可回退）：
    - **无论解析在哪一步失败，都保证 pe.close() 被执行**，句柄不泄漏
    - **所有异常统一翻译为 PeParseError**，避免调用方（CLI/GUI）收到裸 traceback
    - 超过 MAX_FILE_SIZE 的文件直接拒绝，防止恶意大文件耗尽内存
    - 纯静态：不加载、不执行样本；签名校验只读文件
    """
    lang = lang or get_language()
    pe = None
    try:
        p = Path(path).expanduser()
        if not p.is_file():
            raise PeParseError(t("err.not_found", lang=lang, path=p), exit_code=1)

        size = p.stat().st_size
        if size > MAX_FILE_SIZE:
            raise PeParseError(
                t("err.too_large", lang=lang, size=human_size(size),
                  limit=human_size(MAX_FILE_SIZE)),
                exit_code=1,
            )

        pe = pefile.PE(str(p), fast_load=True)
        pe.parse_data_directories(
            directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
            ]
        )
        return _build_report(pe, p, lang)
    except PeParseError:
        raise
    except pefile.PEFormatError as exc:
        raise PeParseError(t("err.not_pe", lang=lang, err=exc), exit_code=2) from exc
    except OSError as exc:
        raise PeParseError(t("err.unreadable", lang=lang, err=exc), exit_code=1) from exc
    except MemoryError as exc:
        raise PeParseError(t("err.oom", lang=lang), exit_code=1) from exc
    except Exception as exc:  # noqa: BLE001
        # 畸形 PE 会触发 pefile 内部各种异常（struct.error / ValueError 等），
        # 统一兜住，绝不裸抛给调用方——CLI 会 traceback，GUI 会闪退。
        raise PeParseError(
            t("err.structure", lang=lang, detail=f"{type(exc).__name__}: {exc}"), exit_code=2
        ) from exc
    finally:
        if pe is not None:
            try:
                pe.close()
            except Exception:  # noqa: BLE001
                pass


def _build_report(pe: pefile.PE, p: Path, lang: str) -> PeReport:
    fh = pe.FILE_HEADER
    oh = pe.OPTIONAL_HEADER

    magic = int(oh.Magic)
    if magic == 0x20B:
        kind = t("common.pe32plus", lang=lang)
    elif magic == 0x10B:
        kind = t("common.pe32", lang=lang)
    else:
        kind = t("common.unknown", lang=lang)
    bits = 64 if magic == 0x20B else 32
    stamp = int(fh.TimeDateStamp)
    file_size = int(p.stat().st_size)

    sections: list[SectionInfo] = []
    for s in pe.sections:
        raw_name = s.Name.rstrip(b"\x00").decode("utf-8", errors="replace")
        name = raw_name or "(无名)"
        entropy, sampled = section_entropy(s)
        perms = section_perms(int(s.Characteristics))
        chars = int(s.Characteristics)
        vsize = int(s.Misc_VirtualSize)
        rsize = int(s.SizeOfRawData)
        sections.append(
            SectionInfo(
                name=name,
                virtual_size=vsize,
                raw_size=rsize,
                entropy=entropy,
                characteristics=chars,
                perms=perms,
                perms_zh=perms_to_zh(perms, lang=lang),
                is_suspicious=entropy > ENTROPY_WARN,
                entropy_sampled=sampled,
                suspicious_reasons=check_section_anomaly(
                    raw_name, chars, vsize, rsize, lang=lang),
            )
        )
    suspicious_section_count = sum(1 for s in sections if s.suspicious_reasons)

    imports: list[ImportDLL] = []
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", None) or []:
        dll = entry.dll.decode("utf-8", errors="replace")
        symbols: list[ImportSymbol] = []
        for imp in entry.imports:
            if imp.name:
                symbols.append(
                    ImportSymbol(
                        name=imp.name.decode("utf-8", errors="replace"),
                        ordinal=None,
                    )
                )
            else:
                symbols.append(ImportSymbol(name=None, ordinal=int(imp.ordinal)))
        imports.append(ImportDLL(dll=dll, symbols=symbols, meaning=dll_meaning(dll)))

    risky_imports = _scan_risky_imports(imports)

    exports: list[ExportSymbol] = []
    exp = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    if exp and exp.symbols:
        for sym in exp.symbols:
            exports.append(
                ExportSymbol(
                    ordinal=int(sym.ordinal),
                    rva=int(sym.address),
                    name=sym.name.decode("utf-8", errors="replace") if sym.name else None,
                    forwarder=sym.forwarder.decode("utf-8", errors="replace") if sym.forwarder else None,
                )
            )

    # 字符串提取：strings.exe（外部工具）+ pefile（兜底）双重来源。
    # 分类时传入真实导入/导出函数名与节区名，让 API / DLL / 节区名噪音准确归桶。
    strings_summary = extract_strings(str(p), min_length=5)
    merged_strings = strings_summary.get("merged", [])
    known_apis = {s.display for d in imports for s in d.symbols}
    known_apis |= {e.name for e in exports if e.name}
    known_sections = {s.name.strip() for s in sections if s.name}
    string_classes = classify_strings(
        merged_strings, known_apis=known_apis, known_sections=known_sections
    )

    # 打包器识别（用节区名 + 特征字符串）
    packers = detect_packers([s.name for s in sections], merged_strings)

    # 数字签名校验（只读文件，不执行样本）
    signature = check_signature(pe, str(p))

    warnings: list[str] = []
    # 加载期降级告警（外置词典/翻译表加载失败等）——不再静默
    for key, kwargs in _LOAD_WARNINGS:
        warnings.append(t(key, **kwargs))
    # 字符串提取的截断/降级告警（P1-1 / P1-2）——直接透传可读文案
    warnings.extend(strings_summary.get("warnings", ()))
    if file_size > 200 * 1024 * 1024:
        warnings.append(t("warn.large_file"))

    return PeReport(
        path=str(p),
        file_size=file_size,
        magic=magic,
        kind=kind,
        bits=bits,
        machine=int(fh.Machine),
        machine_name=str(pefile.MACHINE_TYPE.get(fh.Machine, hex(fh.Machine))),
        machine_zh=translate("MACHINE", str(pefile.MACHINE_TYPE.get(fh.Machine, "")), lang=lang),
        subsystem=int(oh.Subsystem),
        subsystem_name=str(pefile.SUBSYSTEM_TYPE.get(oh.Subsystem, str(oh.Subsystem))),
        subsystem_zh=translate("SUBSYSTEM", str(pefile.SUBSYSTEM_TYPE.get(oh.Subsystem, "")), lang=lang),
        time_date_stamp=stamp,
        compile_time_text=fmt_time(stamp, lang=lang),
        time_in_future=_is_future(stamp),
        entry_point_rva=int(oh.AddressOfEntryPoint),
        image_base=int(oh.ImageBase),
        checksum=int(oh.CheckSum),
        num_sections=int(fh.NumberOfSections),
        num_data_directories=int(oh.NumberOfRvaAndSizes),
        sections=sections,
        imports=imports,
        exports=exports,
        risky_imports=risky_imports,
        strings_summary=strings_summary,
        string_count=len(merged_strings),
        string_classes=string_classes,
        packers=packers,
        signature=signature,
        has_imports=bool(imports),
        has_exports=bool(exports),
        has_risky_imports=bool(risky_imports),
        has_packers=bool(packers),
        suspicious_sections=any(s.is_suspicious for s in sections),
        suspicious_section_count=suspicious_section_count,
        lang=lang,
        warnings=warnings,
    )
