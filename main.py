"""Windows PE Inspector —— 命令行版本。

纯静态解析 PE 文件（exe / dll / sys），打印其结构信息。
安全边界：**只读解析，绝不加载、绝不运行样本**。

用法：
    python main.py <PE 文件>              # 默认：基本信息 + 节区表 + 导入表 + 导出表
    python main.py <PE 文件> --header     # 只看文件头
    python main.py <PE 文件> --sections   # 只看节区表（含熵值 / 加壳提示）
    python main.py <PE 文件> --imports    # 只看导入表
    python main.py <PE 文件> --exports    # 只看导出表
    python main.py <PE 文件> --all        # 同上默认

退出码：0 成功 / 1 文件或依赖问题 / 2 不是有效的 PE 文件
"""

from __future__ import annotations

import argparse
import datetime
import sys
from pathlib import Path

# 中文输出在 GBK 控制台下容易报 UnicodeEncodeError，统一切到 UTF-8。
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8", errors="replace")

try:
    import pefile
except ImportError:
    print("[x] 缺少依赖 pefile，请先执行：pip install -r requirements.txt")
    sys.exit(1)

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


def rule(title: str) -> None:
    print()
    print(f"== {title} ==")


def human_size(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n / 1024 / 1024:.1f} MB"


def fmt_time(stamp: int) -> str:
    if not stamp:
        return "(未设置)"
    try:
        dt = datetime.datetime.fromtimestamp(stamp, tz=datetime.timezone.utc)
    except (OverflowError, OSError, ValueError):
        return f"(异常值 {stamp})"
    text = dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    if dt.year > datetime.datetime.now(datetime.timezone.utc).year:
        text += "  [!] 时间戳位于未来，可能被篡改"
    return text


def section_perms(ch: int) -> str:
    return "".join(name for bit, name in SECTION_FLAGS if ch & bit) or "-"


# --------------------------------------------------------------------------
# 各信息块
# --------------------------------------------------------------------------

def show_header(pe: pefile.PE, path: Path) -> None:
    fh = pe.FILE_HEADER
    oh = pe.OPTIONAL_HEADER
    machine = pefile.MACHINE_TYPE.get(fh.Machine, hex(fh.Machine))
    subsystem = pefile.SUBSYSTEM_TYPE.get(oh.Subsystem, str(oh.Subsystem))
    bits = 64 if oh.Magic == 0x20B else 32
    kind = {0x10B: "PE32 (32 位)", 0x20B: "PE32+ (64 位)"}.get(oh.Magic, "未知")

    rule("基本信息")
    print(f"文件       : {path}")
    print(f"大小       : {human_size(path.stat().st_size)}")
    print(f"格式       : {kind}    架构: {machine}")
    print(f"子系统     : {subsystem}")
    print(f"编译时间   : {fmt_time(fh.TimeDateStamp)}")
    print(f"入口点 RVA : 0x{oh.AddressOfEntryPoint:08X}")
    print(f"镜像基址   : 0x{oh.ImageBase:016X}")
    print(f"节区数量   : {fh.NumberOfSections}")
    print(f"校验和     : 0x{oh.CheckSum:08X}")
    print(f"数据目录   : {oh.NumberOfRvaAndSizes} 项")
    print(f"位数判定   : {bits} 位")


def show_sections(pe: pefile.PE) -> bool:
    rule("节区表")
    print(f"{'名称':<10}{'虚拟大小':>12}{'原始大小':>12}{'熵值':>8}  权限")
    print("-" * 62)
    suspect = False
    for s in pe.sections:
        name = s.Name.rstrip(b"\x00").decode("utf-8", errors="replace") or "(无名)"
        entropy = s.get_entropy()
        flag = ""
        if entropy > ENTROPY_WARN:
            flag = "  <== 疑似加壳/加密"
            suspect = True
        print(
            f"{name:<10}{human_size(s.Misc_VirtualSize):>12}"
            f"{human_size(s.SizeOfRawData):>12}{entropy:>8.2f}  {section_perms(s.Characteristics)}{flag}"
        )
    print("-" * 62)
    print(f"熵值阈值 {ENTROPY_WARN}（越接近 8.0 越可能是压缩/加密数据）")
    if suspect:
        print("[!] 存在高熵节区：该文件很可能被加壳或加密。")
    return suspect


def show_imports(pe: pefile.PE) -> None:
    rule("导入表（依赖的 DLL 及其函数）")
    entries = getattr(pe, "DIRECTORY_ENTRY_IMPORT", None)
    if not entries:
        print("(无导入表)")
        return

    total = 0
    for entry in entries:
        dll = entry.dll.decode("utf-8", errors="replace")
        funcs = []
        for imp in entry.imports:
            if imp.name:
                funcs.append(imp.name.decode("utf-8", errors="replace"))
            else:
                funcs.append(f"Ordinal#{imp.ordinal}")
        total += len(funcs)
        print(f"\n{dll}  ({len(funcs)} 个函数)")
        for name in funcs:
            print(f"    {name}")
    print()
    print(f"合计：{len(entries)} 个 DLL，{total} 个函数")


def show_exports(pe: pefile.PE) -> None:
    rule("导出表")
    directory = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    if not directory or not directory.symbols:
        print("(无导出表，通常说明这是可执行程序而非 DLL)")
        return

    print(f"{'序号':>6}  {'RVA':>10}  {'名称':<40} 转发目标")
    print("-" * 78)
    for sym in directory.symbols:
        name = sym.name.decode("utf-8", errors="replace") if sym.name else "(仅序号)"
        forward = sym.forwarder.decode("utf-8", errors="replace") if sym.forwarder else ""
        print(f"{sym.ordinal:>6}  0x{sym.address:08X}  {name:<40} {forward}")
    print("-" * 78)
    print(f"合计：{len(directory.symbols)} 个导出符号")


# --------------------------------------------------------------------------
# 入口
# --------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Windows PE Inspector（命令行版）：纯静态解析 PE 文件，不运行样本",
    )
    parser.add_argument("file", help="要分析的 PE 文件路径（exe / dll / sys）")
    parser.add_argument("--header", action="store_true", help="显示文件头基本信息")
    parser.add_argument("--sections", action="store_true", help="显示节区表（含熵值与加壳提示）")
    parser.add_argument("--imports", action="store_true", help="显示导入表")
    parser.add_argument("--exports", action="store_true", help="显示导出表")
    parser.add_argument("--all", action="store_true", help="显示全部信息（默认行为）")
    args = parser.parse_args()

    path = Path(args.file).expanduser()
    if not path.is_file():
        print(f"[x] 文件不存在：{path}")
        return 1

    try:
        pe = pefile.PE(str(path), fast_load=False)
    except pefile.PEFormatError as exc:
        print(f"[x] 不是有效的 PE 文件：{exc}")
        return 2
    except OSError as exc:
        print(f"[x] 无法读取文件：{exc}")
        return 1

    # 任一细分开关都没给（或显式 --all）时，输出全部
    show_all = args.all or not (args.header or args.sections or args.imports or args.exports)

    try:
        if show_all or args.header:
            show_header(pe, path)
        if show_all or args.sections:
            show_sections(pe)
        if show_all or args.imports:
            show_imports(pe)
        if show_all or args.exports:
            show_exports(pe)
    finally:
        pe.close()

    print()
    print("解析完成（纯静态分析，样本从未被执行）。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
