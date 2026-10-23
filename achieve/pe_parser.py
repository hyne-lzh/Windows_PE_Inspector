"""PE 解析核心：模块编排入口（主入口 + 向后兼容 re-export 层）。

架构（2026-10-18 拆分，原单文件 1728 行 → 按职责拆分，本文件保留为唯一入口）
-----------------------------------------------------------------------------
::

    achieve/
    ├── pe_parser.py       ← 本文件：parse_pe() 编排 + 全量 re-export（对外唯一入口）
    ├── pe_models.py       ← 数据结构层：dataclass / PeParseError / LOAD_WARNINGS
    ├── pe_translations.py ← PE 结构值翻译（内置表 + assets/translations.json）
    ├── pe_format.py       ← 常量 / 人类可读格式化 / 权限 / 熵值计算
    ├── pe_sections.py     ← A5：危险节区属性识别
    ├── pe_debug.py        ← A4：调试目录（PDB 路径 / GUID / Age）
    ├── pe_dlls.py         ← DLL 用途词典（assets/dll_meanings.json）
    ├── pe_risks.py        ← 高危 API 词典 + 导入表扫描
    ├── pe_packer.py       ← 打包器特征识别
    └── pe_signature.py    ← 数字签名校验（Windows Authenticode，含 catalog）

依赖方向单向：``pe_models`` 在最底层，其余子模块只依赖它（+ i18n /
strings_extractor），**不出现循环 import**。本文件 import 全部子模块，
并把它们的公开符号原样 re-export，因此 ``from achieve.pe_parser import X``
（GUI / CLI / 报告导出 / 测试的既有写法）继续有效，无需改调用方。

安全与工程约束（不可回退）
--------------------------
- 只依赖 pefile 与标准库（数字签名校验在 Windows 上用 ctypes 调系统 API）；
  **禁止 import customtkinter / tkinter**。
- 纯静态解析：不加载、不执行样本；签名校验只读文件。
- ``parse_pe()`` 是 GUI / CLI / 导出的**单一真相源**，返回同一 ``PeReport``。
- ``__version__`` 是版本号单一真相源，**必须字面定义在本文件**——
  ``builds.py --sync-version`` 用正则读取本文件内容（不 import），
  改成跨文件引用会导致 .iss 同步失败。
"""

from __future__ import annotations

from pathlib import Path

import pefile

from .i18n import get_language, t
from .pe_debug import (
    _DEBUG_TYPE_NAMES,
    _format_guid,
    _has_path_separator,
    _parse_debug,
)
from .pe_dlls import (
    _BUILTIN_DLL_MEANINGS,
    _load_dll_meanings,
    DLL_MEANINGS,
    DLL_MEANINGS_PATH,
    dll_meaning,
)
from .pe_format import (
    ENTROPY_SAMPLE_SIZE,
    ENTROPY_SAMPLE_THRESHOLD,
    ENTROPY_WARN,
    MAX_FILE_SIZE,
    PACKER_SCAN_LIMIT,
    SECTION_FLAGS,
    _entropy_of,
    _is_future,
    _sampled_data,
    fmt_time,
    human_size,
    perms_to_zh,
    section_entropy,
    section_perms,
)
from .pe_models import (
    LOAD_WARNINGS,
    DebugInfo,
    ExportSymbol,
    ImportDLL,
    ImportSymbol,
    PackerHit,
    PeParseError,
    PeReport,
    RiskyImport,
    SectionInfo,
    SIG_INVALID,
    SIG_KIND_CATALOG,
    SIG_KIND_EMBEDDED,
    SIG_KIND_NONE,
    SIG_NONE,
    SIG_UNKNOWN,
    SIG_VALID,
    SignatureInfo,
)
from .pe_packer import _PACKER_SIGNATURES, detect_packers
from .pe_risks import (
    _BUILTIN_HIGH_RISK_APIS,
    _load_high_risk_apis,
    _scan_risky_imports,
    HIGH_RISK_APIS,
    RISK_DICT_PATH,
)
from .pe_sections import (
    _check_section_anomaly,
    _SECTION_NAME_RE,
    NORMALLY_WRITABLE_SECTIONS,
    SCN_MEM_EXECUTE,
    SCN_MEM_READ,
    SCN_MEM_WRITE,
    SECTION_EXPAND_RATIO,
    check_section_anomaly,
)
from .pe_signature import (
    _read_signature_blob,
    _security_dir_range,
    _win_check_catalog,
    _win_extract_signer,
    _win_verify_file,
    check_signature,
)
from .pe_translations import (
    _BUILTIN_TRANSLATIONS,
    _load_translations,
    _norm_trans_entry,
    TRANSLATIONS,
    TRANSLATIONS_PATH,
    translate,
    translate_pair,
    zh_pair,
)
from .strings_extractor import classify_strings, extract_strings

# 版本号单一真相源（P2-18 根治）：README 状态行、未来计划.md、GUI 标题、CLI --version
# 均引用此处；PEInspectorSetup.iss 由 builds.py --sync-version 自动同步，不再手工维护。
__version__ = "0.6.0"

# 显式导出清单：声明"本模块的公开面"= 全部子模块公开符号 + 本文件的解析入口。
# 带下划线的名称（_parse_debug 等）一并导出，是为了兼容拆分前
# ``achieve.pe_parser._xxx`` 的既有引用（测试 / 历史脚本）。
__all__ = [
    # 本文件
    "__version__", "parse_pe", "_build_report",
    # pe_models
    "LOAD_WARNINGS", "PeParseError", "PeReport", "SectionInfo", "ImportDLL",
    "ImportSymbol", "ExportSymbol", "RiskyImport", "PackerHit", "DebugInfo",
    "SignatureInfo", "SIG_NONE", "SIG_VALID", "SIG_INVALID", "SIG_UNKNOWN",
    "SIG_KIND_NONE", "SIG_KIND_EMBEDDED", "SIG_KIND_CATALOG",
    # pe_translations
    "TRANSLATIONS", "TRANSLATIONS_PATH", "translate", "translate_pair", "zh_pair",
    # pe_format
    "ENTROPY_WARN", "ENTROPY_SAMPLE_THRESHOLD", "ENTROPY_SAMPLE_SIZE",
    "MAX_FILE_SIZE", "PACKER_SCAN_LIMIT", "SECTION_FLAGS", "human_size",
    "fmt_time", "section_perms", "perms_to_zh", "section_entropy",
    # pe_sections
    "check_section_anomaly", "SCN_MEM_EXECUTE", "SCN_MEM_READ", "SCN_MEM_WRITE",
    "NORMALLY_WRITABLE_SECTIONS", "SECTION_EXPAND_RATIO",
    # pe_debug
    "_parse_debug", "_format_guid", "_has_path_separator",
    # pe_dlls
    "DLL_MEANINGS", "DLL_MEANINGS_PATH", "dll_meaning",
    # pe_risks
    "HIGH_RISK_APIS", "RISK_DICT_PATH", "_scan_risky_imports",
    # pe_packer
    "detect_packers",
    # pe_signature
    "check_signature",
]


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
                # A4：不解析则 pe.DIRECTORY_ENTRY_DEBUG 不存在，_parse_debug 恒空
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DEBUG"],
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

    # A4：调试目录（PDB 路径 / GUID / Age）。pdb_paths 仅收集"含真实路径分隔符"
    # 的值——微软发布版常把完整路径剥离为裸文件名（如 "notepad.pdb"），该形态无
    # 溯源价值；has_pdb 语义 = 含至少一条"可用"PDB 路径（见 A4.md 字段注释）。
    debug_entries = _parse_debug(pe, lang)
    pdb_paths = [d.pdb_path for d in debug_entries if _has_path_separator(d.pdb_path)]
    has_pdb = bool(pdb_paths)

    warnings: list[str] = []
    # 加载期降级告警（外置词典/翻译表加载失败等）——不再静默
    for key, kwargs in LOAD_WARNINGS:
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
        debug_entries=debug_entries,
        has_pdb=has_pdb,
        pdb_paths=pdb_paths,
        lang=lang,
        warnings=warnings,
    )
