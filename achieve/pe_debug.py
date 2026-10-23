"""A4：调试目录解析（PDB 路径 / GUID / Age / 调试类型）。

调用方需已对 IMAGE_DIRECTORY_ENTRY_DEBUG 执行过 parse_data_directories()，
否则 ``pe.DIRECTORY_ENTRY_DEBUG`` 不存在，本模块返回空列表。

实现要点（均经实测验证，详见 A4.md）：
- 仅 CodeView（Type==2）条目的 ``.entry`` 含 PDB 路径 / GUID / Age；
  pefile 对每条都设 ``entry``，但其余类型多为 None 或结构不同，必须 getattr 兜底；
- PdbFileName 是 bytes 且尾部带结构对齐填充的多个 \\x00，须剔除后再解码；
- ``Signature_String`` 是「32 位 GUID + Age 十六进制」拼接（33 字符），
  取 GUID 必须 ``[:32]``，否则末位 Age 会拼出错误 GUID；
- 微软发布版系统文件常有调试目录但 PdbFileName 为空，**属正常现象**；
- 单条解析全程 try/except：畸形样本的一条坏条目不能拖垮整个解析。

拆分自原 achieve/pe_parser.py（2026-10-18）。
"""

from __future__ import annotations

from .i18n import get_language
from .pe_models import DebugInfo
from .pe_translations import translate

# --------------------------------------------------------------------------
# 调试目录类型（A4：IMAGE_DEBUG_TYPE_*）
# --------------------------------------------------------------------------
# pefile 未内置这些常量（实测源码搜不到），故自建映射表。
# 值为 PE 规范标准名，作 translate("DEBUG_TYPE", 名, ...) 的键。
# 注意：部分资料把 14 写作 "ILO" 系笔误，规范名为 ILTG（增量链接时间戳）；
# 仅 2(CodeView) 携带 PDB 路径/GUID/Age，其余多为元信息条目。
_DEBUG_TYPE_NAMES: dict[int, str] = {
    0: "Unknown",
    1: "Coff",
    2: "CodeView",
    3: "FPO",
    4: "Misc",
    5: "Exception",
    6: "Fixup",
    7: "OmapToSrc",
    8: "OmapFromSrc",
    9: "Borland",
    10: "Reserved10",
    11: "CLSID",
    12: "VCFeature",
    13: "POGO",
    14: "ILTG",
    15: "MPX",
    16: "Repro",
    20: "ExDllCharacteristics",
}


def _format_guid(sig: str) -> str:
    """把 32 位十六进制串格式化为标准 GUID；长度或字符不合法一律返回 ""。"""
    s = (sig or "").strip().upper()
    if len(s) != 32 or any(c not in "0123456789ABCDEF" for c in s):
        return ""
    return f"{s[0:8]}-{s[8:12]}-{s[12:16]}-{s[16:20]}-{s[20:32]}"


def _parse_debug(pe, lang: str | None = None) -> list[DebugInfo]:
    """解析调试目录，返回 DebugInfo 列表（A4）。"""
    lang = lang or get_language()
    out: list[DebugInfo] = []
    for e in getattr(pe, "DIRECTORY_ENTRY_DEBUG", None) or []:
        try:
            debug_type = int(e.struct.Type)
            timestamp = int(e.struct.TimeDateStamp)
            name = _DEBUG_TYPE_NAMES.get(debug_type, "")
            # 未知类型不在表内：default 兜底显示原始值，保证 type_text 非空
            type_text = translate("DEBUG_TYPE", name,
                                default=name or str(debug_type), lang=lang)

            entry = getattr(e, "entry", None)  # 仅 CodeView 的 entry 含 PDB 字段，其余多为 None
            pdb_path = ""
            pdb_name = ""
            guid = ""
            age = 0
            cv_signature = ""
            if entry is not None:
                raw = getattr(entry, "PdbFileName", b"")
                if isinstance(raw, str):
                    # 容错：个别 pefile 版本/样本可能直接给 str
                    pdb_path = raw.rstrip("\x00")
                elif isinstance(raw, (bytes, bytearray)):
                    pdb_path = bytes(raw).rstrip(b"\x00").decode("utf-8", errors="replace")
                # 不用 pathlib：Windows 路径含反斜杠，Linux 下 PureWindowsPath 才认，
                # 这里手工切分最稳妥
                pdb_name = pdb_path.replace("\\", "/").rsplit("/", 1)[-1]
                # pefile 的 Signature_String 是「32 位 GUID + Age 十六进制」拼接
                # （pefile.py: uuid.UUID(...).replace("-","").upper() + f"{Age:X}"，
                #   实测 RSDS 样本为 33 字符），须取前 32 位才是 GUID；
                # NB10 老条目无该属性，getattr 兜底为 ""
                sig = str(getattr(entry, "Signature_String", "") or "")[:32]
                guid = _format_guid(sig)
                cv_raw = getattr(entry, "CvSignature", b"")
                if isinstance(cv_raw, (bytes, bytearray)):
                    cv_signature = bytes(cv_raw).decode("ascii", errors="replace")
                elif isinstance(cv_raw, str):
                    cv_signature = cv_raw
                age = int(getattr(entry, "Age", 0) or 0)
            out.append(DebugInfo(
                debug_type=debug_type,
                type_text=type_text,
                pdb_path=pdb_path,
                pdb_name=pdb_name,
                guid=guid,
                age=age,
                timestamp=timestamp,
                cv_signature=cv_signature,
            ))
        except Exception:  # noqa: BLE001
            # 畸形样本的单个坏条目（字段缺失/类型异常/解码失败）不应拖垮整个解析，
            # 跳过该条、继续处理其余条目
            continue
    return out


def _has_path_separator(pdb_path: str) -> bool:
    """PdbFileName 是否含真实路径分隔符（区别于仅裸文件名）。

    微软发布版常把完整路径剥离为裸文件名（如 "notepad.pdb"），该形态不含
    编译机目录信息、无溯源价值，汇总 has_pdb / pdb_paths 时须据此过滤。
    """
    return "\\" in pdb_path or "/" in pdb_path
