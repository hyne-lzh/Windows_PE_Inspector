"""报告导出模块：将已解析好的 PeReport 导出为 HTML 或 Excel。

本模块**不依赖** pe_parser（不 import 它），只通过 duck typing / getattr
防御性地读取传入的 report 对象，便于 PeReport 在未来新增字段（如 strings）
时保持兼容。

- export_html(report, out_path)  -> 自包含单文件 HTML（CSS 内联）
- export_excel(report, out_path) -> openpyxl 多工作表 xlsx
- export_report(report, out_path, fmt) -> 统一入口，按 fmt 或扩展名分派

工程约束：
- 只用标准库 + openpyxl；HTML 手写，无模板引擎、无外部资源
- 写文件一律 encoding="utf-8"
- 路径用 pathlib.Path 处理
- 文件写入失败抛中文异常（调用方处理）
- 不调用 exit()（用 sys.exit），不写 assert（编译期会被剥离）
"""

from __future__ import annotations

import datetime
import html
import sys
from pathlib import Path
from typing import Any

__all__ = ["export_html", "export_excel", "export_report"]

# 风险等级 -> 颜色（HTML 文本色 / Excel 字体色），统一三档着色
RISK_COLORS = {
    "严重": "#c0392b",   # 红
    "中等": "#e67e22",   # 橙
    "低":   "#7f8c8d",   # 灰
}
RISK_COLOR_DEFAULT = "#34495e"
RISK_LEVELS = ("严重", "中等", "低")


# --------------------------------------------------------------------------
# 防御性读取 & 通用工具
# --------------------------------------------------------------------------

def _g(obj: Any, name: str, default: Any = None) -> Any:
    """安全取值：report 或其子对象未定义某字段时回退到 default。"""
    try:
        return getattr(obj, name, default)
    except Exception:
        return default


def _human_size(n: Any) -> str:
    """字节数转可读字符串。无法转数值时原样返回。"""
    try:
        n = int(n)
    except (TypeError, ValueError):
        return str(n)
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n / 1024 / 1024:.1f} MB"


def _hex(value: Any, width: int = 8) -> str:
    """整数转 0x 前缀十六进制；非法值回退为 str。"""
    try:
        return f"0x{int(value):0{width}X}"
    except (TypeError, ValueError):
        return str(value)


def _now_text() -> str:
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _esc(value: Any) -> str:
    """HTML 转义。None 当空串。"""
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


# HTML 报告里字符串区块最多渲染的条数（超出部分省略提示）
MAX_HTML_STRING_ITEMS = 2000

# Excel 公式注入防护：openpyxl 会把以这些前缀开头的字符串标记为公式，
# 而 DLL 名 / 函数名 / 节名都来自被分析的（可能是恶意的）样本，攻击者可构造
# 以 "=" 开头的名字，让分析员打开 xlsx 时触发公式执行或外链请求。
_EXCEL_FORMULA_PREFIXES = ("=", "+", "-", "@")


def _excel_safe(value: Any) -> Any:
    """把不可信文本中和为 Excel 安全值（非字符串原样返回）。"""
    if not isinstance(value, str):
        return value
    # 去掉 NUL 与控制字符（Excel 不接受，且可能用于绕过）
    cleaned = value.replace("\x00", "")
    if cleaned.startswith(_EXCEL_FORMULA_PREFIXES):
        return "'" + cleaned
    return cleaned


def _ws_append(ws, values) -> None:
    """写 Excel 行的统一入口——所有文本先过公式中和，避免逐处遗漏。"""
    ws.append([_excel_safe(v) for v in values])


def _iter_attr(seq: Any, name: str):
    """遍历对象集合并取出某属性，过滤掉 None。"""
    if not seq:
        return []
    out = []
    for item in seq:
        v = _g(item, name)
        if v is not None:
            out.append(v)
    return out


# --------------------------------------------------------------------------
# 数据提取（统一从 report 读取，供 HTML / Excel 共用）
# --------------------------------------------------------------------------

def _basic_rows(report: Any) -> list[tuple[str, str]]:
    """基本信息：两列（项目 / 值）。"""
    rows = [
        ("文件路径", _g(report, "path", "")),
        ("文件大小", _human_size(_g(report, "file_size", 0))),
        ("格式", _g(report, "kind", "")),
        ("位数", f"{_g(report, 'bits', '')} 位"),
        ("架构", _g(report, "machine_name", "")),
        ("子系统", _g(report, "subsystem_name", "")),
        ("编译时间", _g(report, "compile_time_text", "(未设置)")),
        ("入口点 RVA", _hex(_g(report, "entry_point_rva", 0), 8)),
        ("镜像基址", _hex(_g(report, "image_base", 0), 16)),
        ("节区数量", str(_g(report, "num_sections", ""))),
        ("数据目录", f"{_g(report, 'num_data_directories', '')} 项"),
        ("校验和", _hex(_g(report, "checksum", 0), 8)),
    ]
    return [(k, _esc(v)) for k, v in rows]


def _get_sections(report: Any) -> list:
    return _g(report, "sections", []) or []


def _get_imports(report: Any) -> list:
    return _g(report, "imports", []) or []


def _get_exports(report: Any) -> list:
    return _g(report, "exports", []) or []


def _get_risky(report: Any) -> list:
    return _g(report, "risky_imports", []) or []


def _risk_stat(risky: list) -> dict:
    stat = {lv: 0 for lv in RISK_LEVELS}
    for x in risky:
        lv = _g(x, "risk_level", "")
        if lv in stat:
            stat[lv] += 1
    return stat


# ==========================================================================
# HTML 导出
# ==========================================================================

def _html_section_table(sections: list) -> str:
    if not sections:
        return '<p class="empty">（无节区信息）</p>'
    head = (
        "<tr>"
        "<th>名称</th><th>虚拟大小</th><th>原始大小</th>"
        "<th>熵值</th><th>权限</th><th>中文含义</th><th>标记</th>"
        "</tr>"
    )
    body = []
    for s in sections:
        suspicious = bool(_g(s, "is_suspicious", False))
        row_cls = ' class="suspicious"' if suspicious else ""
        mark = "⚠ 高熵·疑似加壳/加密" if suspicious else "正常"
        entropy = _g(s, "entropy", 0.0)
        try:
            entropy_text = f"{float(entropy):.3f}"
        except (TypeError, ValueError):
            entropy_text = str(entropy)
        body.append(
            f"<tr{row_cls}>"
            f"<td>{_esc(_g(s, 'name', ''))}</td>"
            f"<td>{_human_size(_g(s, 'virtual_size', 0))}</td>"
            f"<td>{_human_size(_g(s, 'raw_size', 0))}</td>"
            f"<td>{entropy_text}</td>"
            f"<td>{_esc(_g(s, 'perms', ''))}</td>"
            f"<td>{_esc(_g(s, 'perms_zh', ''))}</td>"
            f"<td class='{'warn' if suspicious else 'ok'}'>{mark}</td>"
            "</tr>"
        )
    return f'<table class="data">{head}{"".join(body)}</table>'


def _html_imports(imports: list) -> str:
    if not imports:
        return '<p class="empty">（无导入表）</p>'
    out = []
    total = 0
    for dll in imports:
        symbols = _g(dll, "symbols", []) or []
        total += len(symbols)
        out.append(
            f'<div class="dll"><span class="dllname">{_esc(_g(dll, "dll", ""))}</span>'
            f' <span class="count">{len(symbols)} 个函数</span></div>'
        )
        if symbols:
            items = "".join(
                f"<li>{_esc(_g(sym, 'display', '(未知)'))}</li>" for sym in symbols
            )
            out.append(f'<ul class="syms">{items}</ul>')
    out.append(f'<p class="total">合计：{len(imports)} 个 DLL，{total} 个函数</p>')
    return "\n".join(out)


def _html_exports(exports: list) -> str:
    if not exports:
        return '<p class="empty">（无导出表，通常说明这是可执行程序而非 DLL）</p>'
    head = "<tr><th>序号</th><th>RVA</th><th>名称</th><th>转发目标</th></tr>"
    body = []
    for e in exports:
        name = _g(e, "name") or "(仅序号)"
        forward = _g(e, "forwarder") or "—"
        body.append(
            "<tr>"
            f"<td>{_g(e, 'ordinal', '')}</td>"
            f"<td>{_hex(_g(e, 'rva', 0), 8)}</td>"
            f"<td>{_esc(name)}</td>"
            f"<td>{_esc(forward)}</td>"
            "</tr>"
        )
    return (
        f'<table class="data">{head}{"".join(body)}</table>'
        f'<p class="total">合计：{len(exports)} 个导出符号</p>'
    )


def _html_risky(risky: list) -> str:
    if not risky:
        return '<p class="empty ok-text">[ok] 未匹配到高危 API</p>'
    head = "<tr><th>等级</th><th>分类</th><th>DLL</th><th>函数</th><th>说明</th></tr>"
    body = []
    for x in risky:
        lv = _g(x, "risk_level", "")
        color = RISK_COLORS.get(lv, RISK_COLOR_DEFAULT)
        body.append(
            "<tr>"
            f'<td style="color:{color};font-weight:bold">{_esc(lv)}</td>'
            f"<td>{_esc(_g(x, 'category', ''))}</td>"
            f"<td>{_esc(_g(x, 'dll', ''))}</td>"
            f"<td>{_esc(_g(x, 'function', ''))}</td>"
            f"<td>{_esc(_g(x, 'description', ''))}</td>"
            "</tr>"
        )
    stat = _risk_stat(risky)
    summary = (
        f"合计 {len(risky)} 个　严重 {stat['严重']}　"
        f"中等 {stat['中等']}　低 {stat['低']}"
    )
    return (
        f'<table class="data">{head}{"".join(body)}</table>'
        f'<p class="total">{summary}</p>'
    )


def _html_strings(report: Any) -> str | None:
    """字符串区块。

    PeReport 的真实字段是 `string_classes`（{类别: [值]}）与 `strings_summary`（含 merged）。
    旧版读的是并不存在的 `report.strings`，导致该区块永远不生成——已修正。
    """
    strings = _g(report, "string_classes", None)
    if not strings:
        summary = _g(report, "strings_summary", {}) or {}
        strings = summary.get("merged", [])
    if not strings:
        return None
    items = []
    if isinstance(strings, dict):
        # 兼容 {category: [values, ...]} 或 {key: value}
        for k, v in strings.items():
            if isinstance(v, (list, tuple)):
                for item in v:
                    items.append(f"[{_esc(k)}] {_esc(item)}")
            else:
                items.append(f"[{_esc(k)}] {_esc(v)}")
    elif isinstance(strings, (list, tuple)):
        for item in strings:
            if isinstance(item, dict):
                items.append(_esc(item.get("value", item.get("string", item))))
            else:
                items.append(_esc(item))
    else:
        items.append(_esc(strings))

    if not items:
        return None
    # 限制渲染条数：恶意/超大样本可能有几十万条字符串，全量写入会把 HTML 撑爆
    total = len(items)
    if total > MAX_HTML_STRING_ITEMS:
        items = items[:MAX_HTML_STRING_ITEMS]
        items.append(f"... 其余 {total - MAX_HTML_STRING_ITEMS} 条未列出（避免报告过大）")
    body = "\n".join(f"<div class='strline'>{it}</div>" for it in items)
    return f'<div class="strings">{body}</div>'


def _html_risk_summary(report: Any, sections: list, risky: list) -> str:
    suspicious_sections = bool(_g(report, "suspicious_sections", False))
    n_susp = sum(1 for s in sections if _g(s, "is_suspicious", False))
    stat = _risk_stat(risky)
    parts = [
        f"高熵节区：{'是（%d 个）' % n_susp if suspicious_sections else '否'}",
        f"高危 API：{len(risky)} 个（严重 {stat['严重']} · 中等 {stat['中等']} · 低 {stat['低']}）",
    ]
    return "<br>".join(parts)


def _html_warning_banner(report: Any, sections: list, risky: list) -> str:
    suspicious_sections = bool(_g(report, "suspicious_sections", False))
    has_risky = bool(_get_risky(report))
    if not (suspicious_sections or has_risky):
        return ""
    reasons = []
    if suspicious_sections:
        reasons.append("存在高熵节区（疑似加壳/加密）")
    if has_risky:
        reasons.append(f"检出 {len(risky)} 个高危 API")
    return (
        '<div class="banner">'
        '⚠ 风险提示：' + "；".join(reasons) + "（纯静态分析，样本从未被执行）"
        '</div>'
    )


_HTML_CSS = """
* { box-sizing: border-box; }
body { font-family: "Microsoft YaHei", "Segoe UI", system-ui, sans-serif;
       margin: 0; padding: 24px; background: #f5f6f8; color: #2c3e50; }
h1 { font-size: 22px; margin: 0 0 4px; }
.subtitle { color: #7f8c8d; font-size: 13px; margin-bottom: 16px; }
.banner { background: #fdecea; border: 1px solid #f5c6cb; color: #c0392b;
          padding: 12px 16px; border-radius: 8px; font-weight: bold;
          margin-bottom: 18px; }
.summary { background: #fff; border: 1px solid #dfe4ea; border-radius: 8px;
           padding: 14px 18px; margin-bottom: 18px; line-height: 1.8; }
.summary .label { font-weight: bold; }
section { background: #fff; border: 1px solid #dfe4ea; border-radius: 8px;
          padding: 16px 18px; margin-bottom: 18px; }
section h2 { font-size: 16px; margin: 0 0 12px; border-left: 4px solid #3498db;
             padding-left: 8px; }
table.data { border-collapse: collapse; width: 100%; font-size: 13px; }
table.data th { background: #3498db; color: #fff; text-align: left;
                padding: 8px 10px; }
table.data td { border: 1px solid #ecf0f1; padding: 6px 10px; }
table.data tr:nth-child(even) td { background: #fafbfc; }
table.data tr.suspicious td { background: #fdecea !important; color: #c0392b;
                              font-weight: bold; }
td.warn { color: #c0392b; font-weight: bold; }
td.ok { color: #27ae60; }
.empty { color: #b2bec3; font-style: italic; }
.ok-text { color: #27ae60; }
.dll { margin-top: 8px; }
.dllname { font-weight: bold; color: #2980b9; }
.count { color: #7f8c8d; font-size: 12px; }
ul.syms { margin: 4px 0 4px 18px; font-size: 13px; color: #34495e; }
.total { color: #7f8c8d; font-size: 13px; margin-top: 8px; }
.strings { max-height: 420px; overflow: auto; background: #2d3436; color: #dfe6e9;
           padding: 12px; border-radius: 6px; font-family: Consolas, monospace;
           font-size: 12px; }
.strline { white-space: pre-wrap; word-break: break-all; padding: 1px 0; }
footer { color: #b2bec3; font-size: 12px; text-align: center; margin-top: 8px; }
"""


def export_html(report: Any, out_path: Any) -> str:
    """导出为自包含单文件 HTML（CSS 内联，无外部依赖）。返回实际写入路径。"""
    out = Path(out_path).expanduser().resolve()
    try:
        out.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise RuntimeError(f"无法创建输出目录 {out.parent}：{exc}") from exc

    sections = _get_sections(report)
    imports = _get_imports(report)
    exports = _get_exports(report)
    risky = _get_risky(report)

    filename = Path(_g(report, "path", "") or "未知文件").name
    title = f"PE 分析报告 · {_esc(filename)}"
    banner = _html_warning_banner(report, sections, risky)
    summary = _html_risk_summary(report, sections, risky)
    strings_html = _html_strings(report)

    blocks = [f'<section><h2>基本信息</h2>{_html_basic_table(report)}</section>']
    blocks.append(f'<section><h2>节区表</h2>{_html_section_table(sections)}</section>')
    blocks.append(f'<section><h2>导入表</h2>{_html_imports(imports)}</section>')
    blocks.append(f'<section><h2>导出表</h2>{_html_exports(exports)}</section>')
    blocks.append(f'<section><h2>高危 API</h2>{_html_risky(risky)}</section>')
    if strings_html is not None:
        blocks.append(f'<section><h2>字符串</h2>{strings_html}</section>')

    doc = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>{_HTML_CSS}</style>
</head>
<body>
<h1>{title}</h1>
<div class="subtitle">分析时间：{_now_text()}　|　Windows PE Inspector（纯静态分析）</div>
{banner}
<div class="summary"><span class="label">风险摘要：</span><br>{summary}</div>
{''.join(blocks)}
<footer>本报告由 Windows PE Inspector 生成 · 仅基于静态解析，不执行样本</footer>
</body>
</html>
"""
    try:
        out.write_text(doc, encoding="utf-8")
    except OSError as exc:
        raise RuntimeError(f"写入 HTML 文件失败 {out}：{exc}") from exc
    return str(out)


def _html_basic_table(report: Any) -> str:
    rows = _basic_rows(report)
    head = "<tr><th>项目</th><th>值</th></tr>"
    body = "".join(
        f"<tr><td class='k'>{_esc(k)}</td><td>{v}</td></tr>" for k, v in rows
    )
    return f'<table class="data">{head}{body}</table>'


# ==========================================================================
# Excel 导出
# ==========================================================================

def _excel_autofit(ws, max_width: int = 60) -> None:
    """依据内容最大显示宽度设置列宽（中文字符按 2 计）。"""
    from openpyxl.utils import get_column_letter

    widths: dict[int, int] = {}
    for row in ws.iter_rows():
        for cell in row:
            if cell.value is None:
                continue
            text = str(cell.value)
            disp = sum(2 if ord(c) > 0x2E80 else 1 for c in text)
            col = cell.column
            widths[col] = max(widths.get(col, 0), disp)
    for col, w in widths.items():
        letter = get_column_letter(col)
        ws.column_dimensions[letter].width = min(w + 2, max_width)


def _excel_style_header(ws) -> None:
    from openpyxl.styles import Alignment, Font, PatternFill

    header_fill = PatternFill(fill_type="solid", fgColor="3498DB")
    header_font = Font(bold=True, color="FFFFFF")
    align = Alignment(horizontal="left", vertical="center")
    for cell in ws[1]:
        if cell.value is None:
            continue
        cell.fill = header_fill
        cell.font = header_font
        cell.alignment = align
    ws.freeze_panes = "A2"


def _excel_basic(ws, report: Any) -> None:
    _ws_append(ws, ["项目", "值"])
    for k, v in _basic_rows(report):
        _ws_append(ws, [k, v])


def _excel_sections(ws, sections: list) -> None:
    from openpyxl.styles import Font, PatternFill

    _ws_append(ws, ["名称", "虚拟大小", "原始大小", "熵值", "权限", "中文含义", "标记"])
    red_fill = PatternFill(fill_type="solid", fgColor="FDECEA")
    red_font = Font(color="C0392B", bold=True)
    for s in sections:
        suspicious = bool(_g(s, "is_suspicious", False))
        entropy = _g(s, "entropy", 0.0)
        try:
            entropy_val = round(float(entropy), 3)
        except (TypeError, ValueError):
            entropy_val = entropy
        mark = "高熵·疑似加壳/加密" if suspicious else "正常"
        _ws_append(ws, [
            _g(s, "name", ""),
            _human_size(_g(s, "virtual_size", 0)),
            _human_size(_g(s, "raw_size", 0)),
            entropy_val,
            _g(s, "perms", ""),
            _g(s, "perms_zh", ""),
            mark,
        ])
        if suspicious:
            for cell in ws[ws.max_row]:
                cell.fill = red_fill
                cell.font = red_font


def _excel_imports(ws, imports: list) -> None:
    _ws_append(ws, ["DLL", "函数", "来源"])
    for dll in imports:
        symbols = _g(dll, "symbols", []) or []
        if not symbols:
            _ws_append(ws, [_g(dll, "dll", ""), "(无函数)", "—"])
            continue
        for sym in symbols:
            name = _g(sym, "name")
            ordinal = _g(sym, "ordinal")
            if name is not None:
                disp, src = name, "名称"
            elif ordinal is not None:
                disp, src = f"Ordinal#{ordinal}", "序号"
            else:
                disp, src = "(未知)", "—"
            _ws_append(ws, [_g(dll, "dll", ""), disp, src])


def _excel_exports(ws, exports: list) -> None:
    _ws_append(ws, ["序号", "RVA", "名称", "转发目标"])
    for e in exports:
        name = _g(e, "name") or "(仅序号)"
        forward = _g(e, "forwarder") or "—"
        _ws_append(ws, [_g(e, "ordinal", ""), _hex(_g(e, "rva", 0), 8), name, forward])


def _excel_risky(ws, risky: list) -> None:
    from openpyxl.styles import Font

    _ws_append(ws, ["等级", "分类", "DLL", "函数", "说明"])
    for x in risky:
        lv = _g(x, "risk_level", "")
        color = RISK_COLORS.get(lv, RISK_COLOR_DEFAULT).lstrip("#")
        _ws_append(ws, [
            lv, _g(x, "category", ""), _g(x, "dll", ""),
            _g(x, "function", ""), _g(x, "description", ""),
        ])
        font = Font(color=color, bold=(lv == "严重"))
        for cell in ws[ws.max_row]:
            cell.font = font


def export_excel(report: Any, out_path: Any) -> str:
    """导出为 Excel（openpyxl，多工作表）。返回实际写入路径。"""
    try:
        from openpyxl import Workbook
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "导出 Excel 需要 openpyxl，请先安装：pip install openpyxl"
        ) from exc

    out = Path(out_path).expanduser().resolve()
    try:
        out.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise RuntimeError(f"无法创建输出目录 {out.parent}：{exc}") from exc

    sections = _get_sections(report)
    imports = _get_imports(report)
    exports = _get_exports(report)
    risky = _get_risky(report)

    wb = Workbook()
    ws_basic = wb.active
    ws_basic.title = "基本信息"
    _excel_basic(ws_basic, report)

    ws_sec = wb.create_sheet("节区")
    _excel_sections(ws_sec, sections)

    ws_imp = wb.create_sheet("导入表")
    _excel_imports(ws_imp, imports)

    ws_exp = wb.create_sheet("导出表")
    _excel_exports(ws_exp, exports)

    ws_risk = wb.create_sheet("高危 API")
    _excel_risky(ws_risk, risky)

    for ws in wb.worksheets:
        _excel_style_header(ws)
        _excel_autofit(ws)

    try:
        wb.save(str(out))
    except OSError as exc:
        raise RuntimeError(f"写入 Excel 文件失败 {out}：{exc}") from exc
    return str(out)


# ==========================================================================
# 统一入口
# ==========================================================================

def export_report(report: Any, out_path: Any, fmt: str = "html") -> str:
    """统一导出入口。

    fmt: "html" | "xlsx"；若未显式指定或指定为 "auto"，则按 out_path 扩展名
    自动分派（.html/.htm -> HTML，.xlsx/.xls -> Excel），否则默认 HTML。
    """
    out = Path(out_path).expanduser().resolve()
    fmt = (fmt or "auto").lower()

    if fmt == "auto":
        suffix = out.suffix.lower()
        if suffix in (".xlsx", ".xls"):
            fmt = "xlsx"
        else:
            fmt = "html"

    if fmt in ("xlsx", "excel"):
        return export_excel(report, out)
    if fmt == "html":
        return export_html(report, out)

    raise ValueError(f"不支持的导出格式：{fmt}（仅支持 html / xlsx）")
