"""Windows PE Inspector —— 命令行版本。

纯静态解析 PE 文件（exe / dll / sys），打印结构信息；绝不加载/运行样本。

用法：
    python cmd_main.py <PE 文件>              # 基本信息 + 节区 + 导入 + 导出 + 高危 API
    python cmd_main.py <PE 文件> --header     # 只看文件头
    python cmd_main.py <PE 文件> --sections   # 只看节区表（含熵值/加壳提示）
    python cmd_main.py <PE 文件> --imports    # 只看导入表
    python cmd_main.py <PE 文件> --exports    # 只看导出表
    python cmd_main.py <PE 文件> --risks      # 只看高危 API
    python cmd_main.py <PE 文件> --packers    # 只看打包器识别
    python cmd_main.py <PE 文件> --signature  # 只看数字签名
    python cmd_main.py <PE 文件> --debug      # 只看调试信息（PDB 路径 / GUID / Age）
    python cmd_main.py <PE 文件> --strings    # 只看字符串
    python cmd_main.py <PE 文件> --export out.html   # 导出 HTML / Excel 报告（--format 可选）
    python cmd_main.py <PE 文件> --lang en    # 英文输出（默认 zh）
    python cmd_main.py --version              # 查看版本号

退出码：0 成功 / 1 文件或依赖问题 / 2 不是有效的 PE 文件
"""

from __future__ import annotations

import argparse
import sys

from achieve import i18n
from achieve.i18n import t
from achieve.pe_parser import (
    ENTROPY_WARN,
    PeParseError,
    __version__,
    human_size,
    parse_pe,
)
from achieve.report_exporter import export_report

# 中文输出在 GBK 控制台下容易报 UnicodeEncodeError，统一切到 UTF-8。
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8", errors="replace")


def rule(title: str) -> None:
    print()
    print(f"== {title} ==")


def _sig_text(report) -> str:
    """签名的单行摘要。"""
    sig = getattr(report, "signature", None)
    if not sig or not getattr(sig, "present", False):
        return t("signature.none")
    status = getattr(sig, "status", "unknown")
    key = {"valid": "signature.valid", "invalid": "signature.invalid"}.get(status, "signature.unknown")
    text = t(key)
    signer = getattr(sig, "signer", "")
    if signer:
        text += f" · {t('signature.signer')}: {signer}"
    issuer = getattr(sig, "issuer", "")
    if issuer:
        text += f" · {t('signature.issuer')}: {issuer}"
    detail = getattr(sig, "detail", "")
    if detail and status == "invalid":
        text += f" ({detail})"
    # 标记签名类别（embedded / catalog）。kind 字段由 pe_parser 提供
    kind = getattr(sig, "kind", "embedded")
    if kind == "catalog":
        text += f" · {t('signature.kind_catalog')}"
    return text


def _packer_names(report) -> str:
    packers = getattr(report, "packers", None) or []
    if not packers:
        return t("packer.none")
    return ", ".join(getattr(p, "name", "") for p in packers)


def show_header(r) -> None:
    rule(t("tab.basic"))
    print(f"{t('info.file'):<12}: {r.path}")
    print(f"{t('info.size'):<12}: {human_size(r.file_size)}")
    print(f"{t('info.format'):<12}: {r.kind}")
    print(f"{t('info.machine'):<12}: {r.machine_name}（{r.machine_zh}）")
    print(f"{t('info.subsystem'):<12}: {r.subsystem_name}（{r.subsystem_zh}）")
    print(f"{t('info.compile_time'):<12}: {r.compile_time_text}")
    print(f"{t('info.entry_point'):<12}: 0x{r.entry_point_rva:08X}")
    print(f"{t('info.image_base'):<12}: 0x{r.image_base:016X}")
    print(f"{t('info.sections_count'):<12}: {r.num_sections}")
    print(f"{t('info.checksum'):<12}: 0x{r.checksum:08X}")
    print(f"{t('info.data_dirs'):<12}: {t('info.unit_items', n=r.num_data_directories)}")
    print(f"{t('info.bits'):<12}: {t('info.unit_bits', n=r.bits)}")
    print(f"{t('packer.title'):<12}: {_packer_names(r)}")
    print(f"{t('signature.title'):<12}: {_sig_text(r)}")
    for w in (r.warnings or []):
        print(f"[!] {w}")


def show_sections(r) -> None:
    rule(t("tab.sections"))
    print(f"{t('sections.col_name'):<12}{t('sections.col_vsize'):>12}{t('sections.col_rsize'):>12}"
          f"{t('sections.col_entropy'):>8}  {t('sections.col_perms'):<10}  {t('sections.col_meaning')}")
    print("-" * 96)
    for s in r.sections:
        flag = f"  <== {t('sections.suspect')}" if s.is_suspicious else ""
        print(
            f"{s.name:<12}{human_size(s.virtual_size):>12}"
            f"{human_size(s.raw_size):>12}{s.entropy:>8.2f}  {s.perms:<10}  {s.perms_zh}{flag}"
        )
    print("-" * 96)
    print(t("cli.entropy_threshold", n=ENTROPY_WARN))
    if r.suspicious_sections:
        print(t("cli.high_entropy_hint"))
    # A5：属性异常的节区单独提示（与"高熵"是两个维度）
    if r.suspicious_section_count:
        print(t("sections.suspect_summary", n=r.suspicious_section_count))
        for s in r.sections:
            if s.suspicious_reasons:
                print(f"  {s.name} : {t('cli.suspect_prefix')}"
                      + t("cli.suspect_join").join(s.suspicious_reasons) + "）")
        print(t("cli.suspect_hint"))


def show_imports(r) -> None:
    rule(t("tab.imports"))
    if not r.has_imports:
        print(t("common.no_imports"))
        return
    total = 0
    for dll in r.imports:
        meaning = f"  — {dll.meaning}" if getattr(dll, "meaning", "") else ""
        print(f"\n{dll.dll}  ({len(dll.symbols)}){meaning}")
        for sym in dll.symbols:
            print(f"    {sym.display}")
        total += len(dll.symbols)
    print()
    print(t("report.imports_total", ndll=len(r.imports), nfun=total))


def show_exports(r) -> None:
    rule(t("tab.exports"))
    if not r.has_exports:
        print(t("common.no_exports"))
        return
    print(f"{t('exports.col_ordinal'):>7}  {t('exports.col_rva'):>10}  "
          f"{t('exports.col_name'):<40} {t('exports.col_forward')}")
    print("-" * 78)
    for sym in r.exports:
        name = sym.name or t("exports.ordinal_only")
        forward = sym.forwarder or ""
        print(f"{sym.ordinal:>7}  0x{sym.rva:08X}  {name:<40} {forward}")
    print("-" * 78)
    print(t("report.exports_total", n=len(r.exports)))


def show_risks(r) -> None:
    rule(t("tab.risks"))
    if not r.has_risky_imports:
        print(t("common.no_risky"))
        return
    from achieve.pe_parser import translate
    print(f"{t('risks.col_risk'):<6}{t('risks.col_category'):<12}{t('risks.col_dll'):<18}"
          f"{t('risks.col_function'):<26}{t('risks.col_desc')}")
    print("-" * 96)
    for x in r.risky_imports:
        level = t(f"risk.{x.risk_level}", default=x.risk_level)
        cat = translate("RISK_CATEGORY", x.category, default=x.category)
        print(f"{level:<6}{cat:<12}{x.dll:<18}{x.function:<26}{x.description}")
    by_level = {"严重": 0, "中等": 0, "低": 0}
    for x in r.risky_imports:
        by_level[x.risk_level] = by_level.get(x.risk_level, 0) + 1
    print("-" * 96)
    print(t("risks.summary", n=len(r.risky_imports), crit=by_level["严重"],
            med=by_level["中等"], low=by_level["低"]))


def show_packers(r) -> None:
    rule(t("packer.title"))
    packers = r.packers or []
    if not packers:
        print(t("packer.none"))
        return
    for p in packers:
        parts = []
        for s in p.sections:
            parts.append(t("packer.evidence_section", name=s))
        for s in p.strings:
            parts.append(t("packer.evidence_string", text=s))
        print(f"  {p.name}: " + ("; ".join(parts) if parts else ""))


def show_signature(r) -> None:
    rule(t("signature.title"))
    print(_sig_text(r))


def show_debug(r) -> None:
    """调试信息区块（A4）。三种情形：无调试目录 / 有目录无 PDB 路径 / 有 PDB 路径。"""
    rule(t("debug.tab"))
    entries = getattr(r, "debug_entries", None) or []
    if not entries:
        print(t("debug.none"))
        return
    print(f"{t('debug.type'):<32}{t('debug.pdb_path')}")
    print("-" * 88)
    for d in entries:
        print(f"{d.type_text:<32}{d.pdb_path or t('common.dash')}")
        # 仅 CodeView 条目有 GUID/Age，单独缩进一行显示，避免主表被撑宽
        detail = []
        if d.guid:
            detail.append(f"{t('debug.guid')}: {d.guid}")
        if d.age:
            detail.append(f"{t('debug.age')}: {d.age}")
        if detail:
            print("    " + "  ".join(detail))
    print("-" * 88)
    print(t("debug.summary", n=len(entries)))
    # has_pdb 为假 = 有调试目录但路径被剥离（微软发布版常见），不是解析失败
    print(t("debug.pdb_hint") if getattr(r, "has_pdb", False) else t("debug.no_pdb"))


def show_strings(r) -> None:
    rule(t("tab.strings"))
    summary = r.strings_summary or {}
    ok = summary.get("external_ok")
    ext = t("strings.ext_ok") if ok else t("strings.ext_fail")
    print(f"{t('strings.summary', source=summary.get('source', '?'), ext=ext, n=r.string_count, counts='').rstrip()}")
    if summary.get("error"):
        print(f"{t('signature.title')}: {summary['error']}")
    classes = r.string_classes or {}
    for key, label in (("urls", "strcls.urls"), ("ips", "strcls.ips"),
                       ("registry", "strcls.registry"), ("paths", "strcls.paths"),
                       ("pdb", "strcls.pdb"), ("xml", "strcls.xml"),
                       ("sections", "strcls.sections"), ("dlls", "strcls.dlls"),
                       ("apis", "strcls.apis")):
        items = classes.get(key) or []
        if items:
            print(t("cli.strings_top_n", label=t(label), n=len(items), k=min(20, len(items))))
            for s in items[:20]:
                print(f"    {s}")
    others = classes.get("others") or []
    if others:
        print(t("cli.strings_others", k=min(10, len(others))))
        for s in others[:10]:
            print(f"    {s}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Windows PE Inspector（命令行版）：纯静态解析 PE 文件，不运行样本",
    )
    parser.add_argument("file", help="要分析的 PE 文件路径（exe / dll / sys）")
    parser.add_argument("--header", action="store_true", help="显示文件头基本信息")
    parser.add_argument("--sections", action="store_true", help="显示节区表（含熵值与加壳提示）")
    parser.add_argument("--imports", action="store_true", help="显示导入表")
    parser.add_argument("--exports", action="store_true", help="显示导出表")
    parser.add_argument("--risks", action="store_true", help="显示高危 API 列表")
    parser.add_argument("--packers", action="store_true", help="显示打包器识别结果")
    parser.add_argument("--signature", action="store_true", help="显示数字签名信息")
    parser.add_argument("--debug", action="store_true", help="显示调试信息（PDB 路径 / GUID / Age）")
    parser.add_argument("--strings", action="store_true", help="显示提取到的字符串")
    parser.add_argument("--export", metavar="PATH", help="导出报告到文件（.html 或 .xlsx）")
    parser.add_argument("--format", choices=["html", "xlsx", "auto"], default="auto",
                        help="导出格式，默认按扩展名自动判断")
    parser.add_argument("--lang", choices=["zh", "en"], default="zh",
                        help="输出语言 / report language (default: zh)")
    parser.add_argument("--all", action="store_true", help="显示全部信息（默认行为）")
    parser.add_argument("--version", action="version", version=f"Windows PE Inspector {__version__}")
    args = parser.parse_args()

    i18n.set_language(args.lang)

    try:
        report = parse_pe(args.file, lang=args.lang)
    except PeParseError as exc:
        print(f"[x] {exc}")
        return exc.exit_code

    show_all = args.all or not (
        args.header or args.sections or args.imports or args.exports
        or args.risks or args.packers or args.signature or args.debug
        or args.strings or args.export
    )

    if show_all or args.header:
        show_header(report)
    if show_all or args.sections:
        show_sections(report)
    if show_all or args.imports:
        show_imports(report)
    if show_all or args.exports:
        show_exports(report)
    if show_all or args.risks:
        show_risks(report)
    if show_all or args.packers:
        show_packers(report)
    if show_all or args.signature:
        show_signature(report)
    if show_all or args.debug:
        show_debug(report)
    if show_all or args.strings:
        show_strings(report)

    if args.export:
        try:
            saved = export_report(report, args.export, fmt=args.format, lang=args.lang)
        except Exception as exc:  # noqa: BLE001
            print(t("cli.export_fail", msg=exc))
            return 1
        print(t("cli.export_ok", path=saved))

    print()
    print(t("cli.done"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
