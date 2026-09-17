"""PE 解析核心：数据结构 + 纯解析逻辑。

只依赖 pefile 与标准库；**禁止 import customtkinter / tkinter**。
解析入口 parse_pe() 返回 PeReport，供命令行与图形界面共用（单一真相源）。
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from pathlib import Path

import pefile

# 节区熵值超过该阈值即提示"疑似加壳/加密"（8.0 为理论上限）
ENTROPY_WARN = 7.2

# 节区特征位（挑常用的）
SECTION_FLAGS = (
    (0x00000020, "CODE"),
    (0x00000040, "IDATA"),
    (0x00000080, "UDATA"),
    (0x20000000, "X"),
    (0x40000000, "R"),
    (0x80000000, "W"),
)


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
    perms: str                  # 如 "CODEXR"
    is_suspicious: bool         # entropy > ENTROPY_WARN


@dataclass
class PeReport:
    path: str
    file_size: int
    magic: int
    kind: str
    bits: int
    machine: int
    machine_name: str
    subsystem: int
    subsystem_name: str
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
    has_imports: bool = False
    has_exports: bool = False
    suspicious_sections: bool = False
    warnings: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------
# 纯格式工具
# --------------------------------------------------------------------------

def human_size(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n / 1024 / 1024:.1f} MB"


def _is_future(stamp: int) -> bool:
    if not stamp:
        return False
    try:
        dt = datetime.datetime.fromtimestamp(stamp, tz=datetime.timezone.utc)
    except (OverflowError, OSError, ValueError):
        return False
    return dt.year > datetime.datetime.now(datetime.timezone.utc).year


def fmt_time(stamp: int) -> str:
    if not stamp:
        return "(未设置)"
    try:
        dt = datetime.datetime.fromtimestamp(stamp, tz=datetime.timezone.utc)
    except (OverflowError, OSError, ValueError):
        return f"(异常值 {stamp})"
    text = dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    if _is_future(stamp):
        text += "  [!] 时间戳位于未来，可能被篡改"
    return text


def section_perms(ch: int) -> str:
    return "".join(name for bit, name in SECTION_FLAGS if ch & bit) or "-"


# --------------------------------------------------------------------------
# 解析
# --------------------------------------------------------------------------

def parse_pe(path) -> PeReport:
    """解析 PE 文件，失败时抛 PeParseError（含中文文案与退出码）。"""
    p = Path(path).expanduser()
    if not p.is_file():
        raise PeParseError(f"文件不存在：{p}", exit_code=1)

    try:
        pe = pefile.PE(str(p), fast_load=True)
        pe.parse_data_directories(
            directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
            ]
        )
    except pefile.PEFormatError as exc:
        raise PeParseError(f"不是有效的 PE 文件：{exc}", exit_code=2) from exc
    except OSError as exc:
        raise PeParseError(f"无法读取文件：{exc}", exit_code=1) from exc

    try:
        return _build_report(pe, p)
    finally:
        pe.close()


def _build_report(pe: pefile.PE, p: Path) -> PeReport:
    fh = pe.FILE_HEADER
    oh = pe.OPTIONAL_HEADER

    magic = int(oh.Magic)
    kind = {0x10B: "PE32 (32 位)", 0x20B: "PE32+ (64 位)"}.get(magic, "未知")
    bits = 64 if magic == 0x20B else 32
    stamp = int(fh.TimeDateStamp)

    sections: list[SectionInfo] = []
    for s in pe.sections:
        name = s.Name.rstrip(b"\x00").decode("utf-8", errors="replace") or "(无名)"
        entropy = float(s.get_entropy())
        sections.append(
            SectionInfo(
                name=name,
                virtual_size=int(s.Misc_VirtualSize),
                raw_size=int(s.SizeOfRawData),
                entropy=entropy,
                characteristics=int(s.Characteristics),
                perms=section_perms(int(s.Characteristics)),
                is_suspicious=entropy > ENTROPY_WARN,
            )
        )

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
        imports.append(ImportDLL(dll=dll, symbols=symbols))

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

    warnings: list[str] = []
    if p.stat().st_size > 200 * 1024 * 1024:
        warnings.append("文件较大（>200 MB），解析可能耗时较长")

    return PeReport(
        path=str(p),
        file_size=int(p.stat().st_size),
        magic=magic,
        kind=kind,
        bits=bits,
        machine=int(fh.Machine),
        machine_name=str(pefile.MACHINE_TYPE.get(fh.Machine, hex(fh.Machine))),
        subsystem=int(oh.Subsystem),
        subsystem_name=str(pefile.SUBSYSTEM_TYPE.get(oh.Subsystem, str(oh.Subsystem))),
        time_date_stamp=stamp,
        compile_time_text=fmt_time(stamp),
        time_in_future=_is_future(stamp),
        entry_point_rva=int(oh.AddressOfEntryPoint),
        image_base=int(oh.ImageBase),
        checksum=int(oh.CheckSum),
        num_sections=int(fh.NumberOfSections),
        num_data_directories=int(oh.NumberOfRvaAndSizes),
        sections=sections,
        imports=imports,
        exports=exports,
        has_imports=bool(imports),
        has_exports=bool(exports),
        suspicious_sections=any(s.is_suspicious for s in sections),
        warnings=warnings,
    )
