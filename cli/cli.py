"""Windows PE Inspector —— 命令行版本。

纯静态解析 PE 文件（exe / dll / sys），打印结构信息；绝不加载/运行样本。

用法：
    python cmd_main.py <PE 文件>              # 基本信息 + 节区表 + 导入表 + 导出表
    python cmd_main.py <PE 文件> --header     # 只看文件头
    python cmd_main.py <PE 文件> --sections   # 只看节区表（含熵值/加壳提示）
    python cmd_main.py <PE 文件> --imports    # 只看导入表
    python cmd_main.py <PE 文件> --exports    # 只看导出表

退出码：0 成功 / 1 文件或依赖问题 / 2 不是有效的 PE 文件
"""

from __future__ import annotations

import argparse
import sys

from achieve.pe_parser import ENTROPY_WARN, PeParseError, human_size, parse_pe

# 中文输出在 GBK 控制台下容易报 UnicodeEncodeError，统一切到 UTF-8。
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8", errors="replace")


def rule(title: str) -> None:
    print()
    print(f"== {title} ==")


def show_header(r) -> None:
    rule("基本信息")
    print(f"文件       : {r.path}")
    print(f"大小       : {human_size(r.file_size)}")
    print(f"格式       : {r.kind}    架构: {r.machine_name}")
    print(f"子系统     : {r.subsystem_name}")
    print(f"编译时间   : {r.compile_time_text}")
    print(f"入口点 RVA : 0x{r.entry_point_rva:08X}")
    print(f"镜像基址   : 0x{r.image_base:016X}")
    print(f"节区数量   : {r.num_sections}")
    print(f"校验和     : 0x{r.checksum:08X}")
    print(f"数据目录   : {r.num_data_directories} 项")
    print(f"位数判定   : {r.bits} 位")


def show_sections(r) -> None:
    rule("节区表")
    print(f"{'名称':<10}{'虚拟大小':>12}{'原始大小':>12}{'熵值':>8}  权限")
    print("-" * 62)
    for s in r.sections:
        flag = "  <== 疑似加壳/加密" if s.is_suspicious else ""
        print(
            f"{s.name:<10}{human_size(s.virtual_size):>12}"
            f"{human_size(s.raw_size):>12}{s.entropy:>8.2f}  {s.perms}{flag}"
        )
    print("-" * 62)
    print(f"熵值阈值 {ENTROPY_WARN}（越接近 8.0 越可能是压缩/加密数据）")
    if r.suspicious_sections:
        print("[!] 存在高熵节区：该文件很可能被加壳或加密。")


def show_imports(r) -> None:
    rule("导入表（依赖的 DLL 及其函数）")
    if not r.has_imports:
        print("(无导入表)")
        return
    total = 0
    for dll in r.imports:
        print(f"\n{dll.dll}  ({len(dll.symbols)} 个函数)")
        for sym in dll.symbols:
            print(f"    {sym.display}")
        total += len(dll.symbols)
    print()
    print(f"合计：{len(r.imports)} 个 DLL，{total} 个函数")


def show_exports(r) -> None:
    rule("导出表")
    if not r.has_exports:
        print("(无导出表，通常说明这是可执行程序而非 DLL)")
        return
    print(f"{'序号':>6}  {'RVA':>10}  {'名称':<40} 转发目标")
    print("-" * 78)
    for sym in r.exports:
        name = sym.name or "(仅序号)"
        forward = sym.forwarder or ""
        print(f"{sym.ordinal:>6}  0x{sym.rva:08X}  {name:<40} {forward}")
    print("-" * 78)
    print(f"合计：{len(r.exports)} 个导出符号")


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

    try:
        report = parse_pe(args.file)
    except PeParseError as exc:
        print(f"[x] {exc}")
        return exc.exit_code

    show_all = args.all or not (args.header or args.sections or args.imports or args.exports)

    if show_all or args.header:
        show_header(report)
    if show_all or args.sections:
        show_sections(report)
    if show_all or args.imports:
        show_imports(report)
    if show_all or args.exports:
        show_exports(report)

    print()
    print("解析完成（纯静态分析，样本从未被执行）。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
