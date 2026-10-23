"""纯格式工具与节区熵计算：无 PE 结构依赖，可独立单测。

包含：
- 大小/时间/权限的格式化（human_size / fmt_time / section_perms / perms_to_zh）
- 采样熵（_entropy_of / _sampled_data / section_entropy）
- 全局阈值常量（ENTROPY_WARN / MAX_FILE_SIZE 等）

拆分自原 achieve/pe_parser.py（2026-10-18）。
"""

from __future__ import annotations

import datetime
import math
from collections import Counter

from .i18n import get_language, t
from .pe_translations import TRANSLATIONS, translate

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
    """Unix 时间戳 → "YYYY-MM-DD HH:MM:SS UTC"；0 或非法值给占位文案。"""
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
    """特性位 → 权限缩写（如 "CODEXR"）；无匹配给 "-"。"""
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

    ``entropy_sampled`` 标志由调用方写入 SectionInfo，供展示层标注
    "该熵值为采样估算"（防止分析员把采样值当精确值解读）。
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
