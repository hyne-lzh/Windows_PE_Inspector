"""A5：危险节区属性识别（规则化判定，可独立单测）。

判定单个节区的属性异常，返回可疑原因列表（空列表 = 正常）。
四条规则见 check_section_anomaly 的 docstring。

拆分自原 achieve/pe_parser.py（2026-10-18）。
"""

from __future__ import annotations

import re

from .i18n import get_language, t

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
