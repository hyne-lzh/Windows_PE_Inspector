"""Windows PE Inspector —— 图形界面（customtkinter）。

选一个 PE 文件 → 后台线程解析 → 七页展示（基本信息 / 调试信息 / 节区 / 导入表 /
导出表 / 高危 API / 字符串）。支持**中英双语切换**（右上角分段按钮，切换后自动重解析）。

线程模型（铁律，不得更改）：
- 解析跑在 ``threading.Thread(daemon=True)`` 里，**绝不触碰任何 widget**；
- 工作线程只通过 ``self._queue`` 回传 ``("ok", report)`` 或 ``("err", 中文文案)``；
- 主线程用 ``self.after(100, self._poll)`` 轮询队列并更新界面。

界面增强：文件拖放（tkinterdnd2）、表格右键复制、每个表格分页顶部实时搜索过滤。

安全边界：纯静态解析，绝不加载/运行样本。
"""

from __future__ import annotations

import datetime
import os
import queue
import threading
import traceback
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import NamedTuple

import customtkinter as ctk

# P1-5：tkinterdnd2 缺失时不应导致整个程序 ImportError 崩溃（打包成无控制台 exe
# 会表现为"双击无反应"）。这里包 try/except，缺失时降级为"无拖放"，
# 由 _enable_drop_target 反映到 UI；customtkinter 为硬依赖，缺失才真无法启动。
try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
    _HAS_TKDND = True
except ImportError:  # pragma: no cover - 环境缺包时的降级路径
    DND_FILES = None  # type: ignore
    TkinterDnD = None  # type: ignore
    _HAS_TKDND = False

from achieve import i18n
from achieve.i18n import t
from achieve.pe_parser import PeParseError, human_size, parse_pe, translate
from achieve.report_exporter import export_report

# --------------------------------------------------------------------------
# 全局常量
# --------------------------------------------------------------------------

WINDOW_W = 1020
WINDOW_H = 680
MIN_W = 880
MIN_H = 560

FONT_FAMILY = "Microsoft YaHei UI"  # 本机已实测可用；不带 UI 的 "Microsoft YaHei" 不存在

# 分页的 i18n 键（顺序即展示顺序）
# A4：调试信息复用既有 debug.tab 键，置于「基本信息」之后（属文件级元数据）
_TAB_KEYS = ("tab.basic", "debug.tab", "tab.sections", "tab.imports",
             "tab.exports", "tab.risks", "tab.strings")

# 字符串分页最多展示的"其他"类条数（超大文件防卡顿，完整内容用导出报告查看）
STRING_OTHERS_LIMIT = 2000

# 字符串分类的展示顺序（key 与 strings_extractor.classify_strings 一致）
_STRING_CLASS_KEYS = ("urls", "ips", "registry", "paths", "pdb",
                      "xml", "sections", "dlls", "apis", "others")

# 风险等级 → 颜色（导入表 / 高危 API 表格共用）
# 用户要求配色：高危红、中危橙、低危黄、安全绿
RISK_COLORS = {
    "严重": "#d13438",   # 红
    "中等": "#e0883a",   # 橙
    "低":   "#e8c547",   # 黄
    "安全": "#2fa572",   # 绿
}

# 等级优先级：用于取某个 DLL 下的"最高风险"给父节点着色
RISK_RANK = {"安全": 0, "低": 1, "中等": 2, "严重": 3}

# 状态栏配色：灰色 / 蓝色 / 绿色 / 红色
STATUS_COLORS = {
    "idle": "#9a9a9a",
    "busy": "#3b8ed0",
    "ok": "#2fa572",
    "error": "#d13438",
}


# 表格行的原始数据。搜索过滤只是"重建显示"，永远从这里取源数据还原。
class _Row(NamedTuple):
    parent: int | None   # 父行在 rows 中的下标（仅树形表格的导入表用到）
    text: str            # show="tree" 表格显示的文本
    values: tuple        # show="headings" 表格的各列
    tags: tuple          # 着色 tag（节区 suspect / 风险等级 risk_xxx）
    opened: bool         # 父节点是否默认展开


class _TableState(NamedTuple):
    tree: ttk.Treeview
    rows: tuple          # tuple[_Row, ...]
    count_label: object  # ctk.CTkLabel，显示"显示 N / 共 M 行"
    is_tree: bool


def parse_dropped_files(data: str) -> list[str]:
    """从 tkdnd 的 ``event.data`` 里解析出文件路径列表。

    Windows 下含空格的路径会被 ``{}`` 包裹，多个文件以空格分隔，形如：
    ``{C:\\Program Files\\a b\\my file.exe} C:\\x.exe``
    因此必须按大括号分组解析，不能简单 split(" ")。
    """
    paths: list[str] = []
    buf: list[str] = []
    in_brace = False
    for ch in (data or ""):
        if ch == "{":
            in_brace = True
            buf = []
        elif ch == "}":
            in_brace = False
            if buf:
                paths.append("".join(buf))
            buf = []
        elif ch == " " and not in_brace:
            if buf:
                paths.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    if buf:
        paths.append("".join(buf))
    # 去掉首尾空白与可能的引号
    return [p.strip().strip('"') for p in paths if p.strip()]


def _row_hit(row: _Row, keyword: str) -> bool:
    """某行的任意单元格 (text / 任一列) 含关键字即命中（不区分大小写）。"""
    for piece in (*row.values, row.text):
        if piece and keyword in str(piece).lower():
            return True
    return False


def _filter_rows(rows: tuple, keyword: str, is_tree: bool) -> set[int]:
    """返回应当显示的行下标集合；关键字为空则全部显示。"""
    if not keyword:
        return set(range(len(rows)))

    shown: set[int] = set()
    if not is_tree:
        for i, row in enumerate(rows):
            if _row_hit(row, keyword):
                shown.add(i)
        return shown

    # 树形表格（导入表）：DLL 父节点命中则整组展示，否则只展示命中的函数，
    # 且父节点自动展开，否则匹配到的子节点会藏在折叠树里看不见。
    children: dict[int, list[int]] = {}
    for i, row in enumerate(rows):
        if row.parent is not None:
            children.setdefault(row.parent, []).append(i)
    for i, row in enumerate(rows):
        if row.parent is not None:
            continue
        if _row_hit(row, keyword):
            shown.add(i)
            shown.update(children.get(i, ()))
        else:
            hits = [j for j in children.get(i, ()) if _row_hit(rows[j], keyword)]
            if hits:
                shown.add(i)
                shown.update(hits)
    return shown


# --------------------------------------------------------------------------
# 日志与全局异常兜底（打包后没有控制台，报错必须可见）
# --------------------------------------------------------------------------

def _log_path() -> Path:
    """返回日志文件路径。

    位置：``%LOCALAPPDATA%\\PEInspector\\pe_inspector.log``；
    取不到 ``LOCALAPPDATA`` 时退到 ``Path.home()``。
    **绝不写入当前工作目录** —— 双击 exe 时 cwd 不可预测。
    """
    base = os.environ.get("LOCALAPPDATA")
    root = Path(base) if base else Path.home()
    return root / "PEInspector" / "pe_inspector.log"


def _log_exception(exc_type, exc_val, exc_tb) -> None:
    """把异常 traceback 追加写入日志文件。写日志失败绝不抛异常。"""
    try:
        path = _log_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            fh.write(f"\n===== {stamp} =====\n")
            traceback.print_exception(exc_type, exc_val, exc_tb, file=fh)
    except Exception:
        pass


def _make_exception_handler(root):
    """构造 ``root.report_callback_exception`` 用的处理器：弹窗 + 写日志。"""

    def handler(exc_type, exc_val, exc_tb):
        _log_exception(exc_type, exc_val, exc_tb)
        try:
            messagebox.showerror(
                t("dlg.error_title"),
                t("dlg.error_msg", path=_log_path(), etype=exc_type.__name__, emsg=exc_val),
            )
        except Exception:
            pass

    return handler


# --------------------------------------------------------------------------
# 主题取色（让 ttk.Treeview 尽量贴合 customtkinter 当前主题）
# --------------------------------------------------------------------------

def apply_treeview_theme(style: ttk.Style) -> None:
    """在已创建的 ttk.Style 上配置 PE.Treeview 主题色（主窗口 __init__ 调用一次）。"""
    style.theme_use("clam")
    dark = ctk.get_appearance_mode() == "Dark"
    # 硬编码兜底色：实测 ctk.ThemeManager.theme 取色慢且字段缺失（CTkTabview 不存在），
    # 直接用稳定值比每次渲染重新解析主题快得多。
    if dark:
        bg, fg, head_bg, sel = "#1d1e1e", "#dce4ee", "#2b2b2b", "#1f6aa5"
    else:
        bg, fg, head_bg, sel = "#f9f9fa", "#1a1a1a", "#e5e5e5", "#3b8ed0"
    style.configure("PE.Treeview", background=bg, foreground=fg,
                    fieldbackground=bg, rowheight=26, borderwidth=0)
    style.configure("PE.Treeview.Heading", background=head_bg, foreground=fg,
                    borderwidth=0, relief="flat")
    style.map("PE.Treeview",
              background=[("selected", sel)],
              foreground=[("selected", "#ffffff")])


# --------------------------------------------------------------------------
# 主窗口
# --------------------------------------------------------------------------

# P1-5：tkinterdnd2 可用时继承其 DnDWrapper 以获得拖放能力；
# 缺失时退化为纯 CTk 窗口（无拖放，其余功能不受影响）。
if _HAS_TKDND:
    _MainWindowBase = (ctk.CTk, TkinterDnD.DnDWrapper)
else:  # pragma: no cover - 环境缺包时的降级路径
    _MainWindowBase = (ctk.CTk,)


class MainWindow(*_MainWindowBase):
    """应用主窗口（tkinterdnd2 可用时同时是拖放目标）。"""

    def __init__(self) -> None:
        ctk.set_appearance_mode("system")
        ctk.set_default_color_theme("blue")

        super().__init__()

        self.title(t("app.title"))
        self.minsize(MIN_W, MIN_H)
        self._center_window()

        # 拖放：tkdnd 加载失败只降级（不启用拖拽），不影响其余功能
        self._dnd_enabled = self._enable_drop_target()

        self.font_normal = ctk.CTkFont(family=FONT_FAMILY, size=13)
        self.font_title = ctk.CTkFont(family=FONT_FAMILY, size=15, weight="bold")

        # ttk.Style 一次性创建；configure 每次渲染调用很轻，但避免反复创建 Style 实例
        self._style = ttk.Style(self)
        apply_treeview_theme(self._style)

        # 线程与队列（契约见模块 docstring）
        self._queue: queue.Queue = queue.Queue()
        self._worker: threading.Thread | None = None
        # P1-4：并发"代际"标识。每次发起解析自增，消息携带代次，
        # _poll 只消费当前代次，避免快速连点时旧链清掉新 worker / 渲染旧数据。
        self._generation = 0
        # 最近一次解析成功的报告（供「导出报告」使用）
        self._report = None

        # 供语言切换时刷新文本的控件引用
        self.label_file = None
        self.label_dnd = None

        self._build_layout()
        self.clear_view()
        self.set_status(t("status.ready"), "idle")

    # ---------------------------------------------------------------- 布局

    def _center_window(self) -> None:
        self.update_idletasks()
        screen_w = self.winfo_screenwidth()
        screen_h = self.winfo_screenheight()
        x = max(0, (screen_w - WINDOW_W) // 2)
        y = max(0, (screen_h - WINDOW_H) // 2)
        self.geometry(f"{WINDOW_W}x{WINDOW_H}+{x}+{y}")

    def _build_layout(self) -> None:
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)
        self._build_path_bar()
        self._build_tabs()
        self._build_status_bar()

    def _build_path_bar(self) -> None:
        bar = ctk.CTkFrame(self, corner_radius=0)
        bar.grid(row=0, column=0, sticky="ew", padx=12, pady=(12, 6))
        bar.grid_columnconfigure(1, weight=1)

        self.label_file = ctk.CTkLabel(bar, text=t("toolbar.file_label"), font=self.font_normal)
        self.label_file.grid(row=0, column=0, padx=(12, 8), pady=12)

        self.path_var = tk.StringVar()
        self.entry = ctk.CTkEntry(bar, textvariable=self.path_var, font=self.font_normal)
        self.entry.grid(row=0, column=1, sticky="ew", padx=(0, 8), pady=12)

        self.btn_browse = ctk.CTkButton(
            bar, text=t("toolbar.browse"), width=90, font=self.font_normal, command=self._browse)
        self.btn_browse.grid(row=0, column=2, padx=(0, 8), pady=12)

        self.btn_analyze = ctk.CTkButton(
            bar, text=t("toolbar.analyze"), width=100, font=self.font_normal, command=self._on_analyze)
        self.btn_analyze.grid(row=0, column=3, padx=(0, 8), pady=12)

        # 导出报告：分析成功后才可用
        self.btn_export = ctk.CTkButton(
            bar, text=t("toolbar.export"), width=90, font=self.font_normal,
            command=self._on_export, state="disabled")
        self.btn_export.grid(row=0, column=4, padx=(0, 8), pady=12)

        # 语言切换：中文 / English
        self.lang_seg = ctk.CTkSegmentedButton(
            bar, values=[t("lang.zh"), t("lang.en")],
            font=self.font_normal, command=self._on_lang_segment)
        self.lang_seg.set(t("lang.zh") if i18n.get_language() == "zh" else t("lang.en"))
        self.lang_seg.grid(row=0, column=5, padx=(0, 12), pady=12)

        if self._dnd_enabled:
            self.label_dnd = ctk.CTkLabel(
                bar, text=t("toolbar.dnd_hint"),
                text_color="gray", font=self.font_normal, anchor="w")
            self.label_dnd.grid(row=1, column=0, columnspan=6, sticky="w", padx=12, pady=(0, 10))

    # ------------------------------------------------------------ 语言切换

    def _on_lang_segment(self, value: str) -> None:
        lang = "zh" if value == t("lang.zh") else "en"
        self._switch_language(lang)

    def _switch_language(self, lang: str) -> None:
        """切换界面语言：刷新静态文案并重建分页；若已选文件则自动重解析。"""
        if lang == i18n.get_language():
            return
        i18n.set_language(lang)

        # 刷新工具栏静态文本
        self.title(t("app.title"))
        if self.label_file is not None:
            self.label_file.configure(text=t("toolbar.file_label"))
        self.btn_browse.configure(text=t("toolbar.browse"))
        self.btn_analyze.configure(text=t("toolbar.analyze"))
        self.btn_export.configure(text=t("toolbar.export"))
        if self.label_dnd is not None:
            self.label_dnd.configure(text=t("toolbar.dnd_hint"))
        self.lang_seg.configure(values=[t("lang.zh"), t("lang.en")])
        self.lang_seg.set(t("lang.zh") if lang == "zh" else t("lang.en"))

        # 分页名随语言变化，需重建
        self._rebuild_tabs()

        # 旧报告失效，禁用导出
        self._report = None
        self.btn_export.configure(state="disabled")

        if self.path_var.get().strip():
            self._on_analyze()      # 用新语言重新解析
        else:
            self.clear_view()
            self.set_status(t("status.ready"), "idle")

    def _rebuild_tabs(self) -> None:
        self.tabs.destroy()
        self._build_tabs()

    # ------------------------------------------------------------ 拖放

    def _enable_drop_target(self) -> bool:
        """把主窗口注册为文件拖放目标。成功返回 True。

        P1-5：tkinterdnd2 未安装（``_HAS_TKDND`` 为 False）时直接返回 False，
        不尝试调用其 API，也不拖累主程序启动。
        """
        if not _HAS_TKDND:
            return False
        try:
            self.TkdndVersion = TkinterDnD._require(self)
            self.drop_target_register(DND_FILES)
            self.dnd_bind("<<Drop>>", self._on_drop)
        except Exception as exc:  # noqa: BLE001  # tkdnd 缺失时降级，不拖累主程序
            _log_exception(type(exc), exc, exc.__traceback__)
            return False
        return True

    def _on_drop(self, event) -> None:
        """拖入文件：解析出第一个路径→填入路径框→自动开始分析。"""
        paths = parse_dropped_files(getattr(event, "data", ""))
        if not paths:
            self.set_status(t("status.drop_bad"), "error")
            return
        self.path_var.set(paths[0])
        self._on_analyze()

    def _build_tabs(self) -> None:
        # 注意：customtkinter 6.0.0 的 CTkTabview 不支持 font 参数（5.x 教程里才有）
        self.tabs = ctk.CTkTabview(self)
        self.tabs.grid(row=1, column=0, sticky="nsew", padx=12, pady=6)
        for key in _TAB_KEYS:
            self.tabs.add(t(key))

    def _build_status_bar(self) -> None:
        bar = ctk.CTkFrame(self, corner_radius=0)
        bar.grid(row=2, column=0, sticky="ew", padx=12, pady=(6, 12))
        bar.grid_columnconfigure(0, weight=1)

        self.status_label = ctk.CTkLabel(bar, text=t("status.ready"), anchor="w", font=self.font_normal)
        self.status_label.grid(row=0, column=0, sticky="ew", padx=(12, 8), pady=8)

        self.progress = ctk.CTkProgressBar(bar, mode="indeterminate", width=160)
        self.progress.grid(row=0, column=1, padx=(0, 12), pady=8)
        self.progress.set(0)

    # ------------------------------------------------------------ 分页取用

    def _page(self, key: str):
        return self.tabs.tab(t(key))

    # ------------------------------------------------------------ 交互动作

    def _browse(self) -> None:
        """弹出文件选择对话框；选中后填入路径并立刻触发解析（与拖入行为一致）。"""
        path = filedialog.askopenfilename(
            title=t("dlg.pick_file"),
            filetypes=[(t("dlg.ft_pe"), "*.exe;*.dll;*.sys"), (t("dlg.ft_all"), "*.*")],
        )
        if path:
            self.path_var.set(path)
            self._on_analyze()

    def _on_export(self) -> None:
        """把当前报告导出为 HTML / Excel（按保存对话框的扩展名自动判断格式）。"""
        if self._report is None:
            self.set_status(t("status.need_analyze"), "error")
            return

        path = filedialog.asksaveasfilename(
            title=t("dlg.save_report"),
            defaultextension=".html",
            filetypes=[(t("dlg.ft_html"), "*.html"), (t("dlg.ft_excel"), "*.xlsx"),
                       (t("dlg.ft_all"), "*.*")],
        )
        if not path:
            return
        try:
            saved = export_report(self._report, path, fmt="auto", lang=i18n.get_language())
        except Exception as exc:  # noqa: BLE001
            self.set_status(t("status.export_failed", msg=exc), "error")
            try:
                messagebox.showerror(t("dlg.export_failed_title"), str(exc))
            except Exception:  # noqa: BLE001
                pass
            return
        self.set_status(t("status.exported", path=saved), "ok")

    def _on_analyze(self) -> None:
        if self._worker is not None and self._worker.is_alive():
            return
        path = self.path_var.get().strip()
        if not path:
            self.set_status(t("status.need_file"), "error")
            return

        self.clear_view()
        self.btn_analyze.configure(state="disabled")
        self.set_status(t("status.parsing"), "busy")
        self.progress.start()

        # P1-4：递增代次并绑定到本次 worker；消息与代次一同回传。
        self._generation += 1
        gen = self._generation
        self._worker = threading.Thread(
            target=self._run_parse, args=(path, gen), daemon=True)
        self._worker.start()
        self.after(100, lambda: self._poll(gen))

    # ------------------------------------------------------------ 线程契约

    def _run_parse(self, path: str, gen: int) -> None:
        """后台线程体：解析 PE 并回传结果。绝不触碰任何 widget。

        P1-4：消息携带发起时的代次 ``gen``，主线程据此丢弃过期结果。
        """
        try:
            report = parse_pe(path, lang=i18n.get_language())
            self._queue.put((gen, "ok", report))
        except PeParseError as exc:
            self._queue.put((gen, "err", str(exc)))
        except Exception as exc:  # noqa: BLE001
            # P2-5：未预期异常也要落盘，避免堆栈丢失
            _log_exception(type(exc), exc, exc.__traceback__)
            self._queue.put((gen, "err", f"{type(exc).__name__}: {exc}"))

    def _poll(self, gen: int) -> None:
        # P1-4：本次轮询链只服务自己那一代；若已有更新的解析发起，直接退场，
        # 避免旧链误清新 worker / 覆盖新结果。
        if gen != self._generation:
            return

        try:
            msg_gen, kind, payload = self._queue.get_nowait()
        except queue.Empty:
            # P1-3：判定"线程异常退出"前必须再取一次队列 —— 工作线程可能在
            # get_nowait 抛 Empty 与 is_alive 检查之间完成 put 并退出，
            # 此时只检查 is_alive 会误判异常退出、永久丢失结果。
            try:
                msg_gen, kind, payload = self._queue.get_nowait()
            except queue.Empty:
                worker = self._worker
                if worker is not None and not worker.is_alive():
                    self._finish_busy(gen)
                    self.set_status(t("status.thread_dead"), "error")
                    return
                self.after(100, lambda: self._poll(gen))
                return

        # 过期代次的消息直接丢弃，并继续监听当前代次
        if msg_gen != gen:
            self.after(100, lambda: self._poll(gen))
            return

        self._finish_busy(gen)
        if kind == "ok":
            # 记住报告，供「导出报告」按钮使用
            self._report = payload
            self.btn_export.configure(state="normal")
            self.render(payload)
            summary = t("status.done", nsec=len(payload.sections), ndll=len(payload.imports))
            if payload.has_risky_imports:
                summary += t("status.done_risky", n=len(payload.risky_imports))
            if payload.string_count:
                summary += t("status.done_strings", n=payload.string_count)
            self.set_status(summary, "ok")
        else:
            # 解析失败：清掉旧报告并禁用导出，避免导出到过期数据
            self._report = None
            self.btn_export.configure(state="disabled")
            self.clear_view()
            self.set_status(t("status.failed", msg=payload), "error")
            try:
                messagebox.showerror(t("dlg.parse_failed_title"), payload)
            except Exception:
                pass

    def _finish_busy(self, gen: int | None = None) -> None:
        """结束忙碌态。P1-4：仅当代次匹配时才清空 worker，避免误清新任务。"""
        if gen is not None and gen != self._generation:
            return
        self.progress.stop()
        self.progress.set(0)
        self.btn_analyze.configure(state="normal")
        self._worker = None

    # ----------------------------------------------- 表格：搜索 + 右键复制

    def _build_search_bar(self, page) -> tuple[tk.StringVar, object]:
        """在分页顶部放一个实时过滤搜索框，返回 (关键字变量, 行数标签)。

        注意必须在 Treeview 之前打包，否则会排在表格下方。
        """
        bar = ctk.CTkFrame(page, fg_color="transparent")
        bar.pack(fill="x", padx=12, pady=(6, 4))
        var = tk.StringVar()
        ctk.CTkEntry(bar, textvariable=var, placeholder_text=t("search.placeholder"),
                     font=self.font_normal, width=240).pack(side="left")
        count = ctk.CTkLabel(bar, text="", text_color="gray", font=self.font_normal)
        count.pack(side="left", padx=(10, 0))
        return var, count

    def _attach_table(self, page, tree, rows, var, count_label, is_tree: bool = False) -> None:
        """挂接搜索 + 右键菜单，灌入数据并完成布局打包。

        ``rows`` 是原始数据，搜索只重建 Treeview 的显示内容，不清数据，
        所以清空关键字一定能还原全部行（tag 着色也跟着一起还原）。
        """
        self._bind_tree_menu(tree)
        state = _TableState(tree, tuple(rows), count_label, is_tree)
        var.trace_add("write", lambda *_: self._apply_search(state, var.get()))

        # 布局：全部用 pack。⚠️ 不要用「中间容器 + tree.grid(in_=holder)」的跨父布局——
        # Treeview 的父容器是 page，把布局目标换成另一个容器时 Tk 不会正确计算尺寸，
        # 表格会整片空白（统计行数正常但看不到任何行）。正确做法：先 pack 滚动条占边缘，
        # 最后 pack tree 让它填满剩余空间。
        ysb = ttk.Scrollbar(page, orient="vertical", command=tree.yview)
        xsb = ttk.Scrollbar(page, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=ysb.set, xscrollcommand=xsb.set)

        xsb.pack(side="bottom", fill="x", padx=12, pady=(0, 10))
        ysb.pack(side="right", fill="y", padx=(0, 12))
        tree.pack(side="left", fill="both", expand=True, padx=(12, 0))

        self._apply_search(state, var.get())

    def _apply_search(self, state: _TableState, keyword: str) -> None:
        """按关键字重建表格显示内容。"""
        tree = state.tree
        if not tree.winfo_exists():  # 分页被重建后旧搜索框可能还没释放
            return
        target = (keyword or "").strip().lower()
        shown = _filter_rows(state.rows, target, state.is_tree)

        tree.delete(*tree.get_children())
        total = 0
        for i, row in enumerate(state.rows):
            if i not in shown:
                continue
            parent = "" if row.parent is None else f"r{row.parent}"
            tree.insert(parent, "end", iid=f"r{i}", text=row.text,
                        values=row.values, tags=row.tags,
                        open=row.opened or bool(target))
            total += 1

        suffix = (t("search.shown", shown=total, total=len(state.rows)) if target
                  else t("search.total", total=len(state.rows)))
        try:
            state.count_label.configure(text=suffix)
        except Exception:  # noqa: BLE001  # 标签随分页销毁
            pass

    def _bind_tree_menu(self, tree) -> None:
        tree.bind("<Button-3>", lambda event: self._popup_tree_menu(tree, event))

    def _popup_tree_menu(self, tree, event) -> None:
        """右键：先选中鼠标所在行再弹菜单。"""
        iid = tree.identify_row(event.y)
        if iid:
            tree.selection_set(iid)
            tree.focus(iid)
        menu = tk.Menu(self, tearoff=0)
        menu.add_command(label=t("menu.copy"), command=lambda: self._copy_tree_rows(tree, all_rows=False))
        menu.add_command(label=t("menu.copy_all"), command=lambda: self._copy_tree_rows(tree, all_rows=True))
        menu.tk_popup(event.x_root, event.y_root)

    def _copy_tree_rows(self, tree, all_rows: bool) -> None:
        """把选中行（或全部显示行）写进剪贴板。树形表格取 text，列表表格取各列。"""
        if all_rows:
            iids = list(self._iter_tree_iids(tree, ""))
        else:
            iids = self._selected_rows_in_order(tree, set(tree.selection()))
        lines = [self._row_to_text(tree, iid) for iid in iids]
        lines = [line for line in lines if line]
        if not lines:
            self.set_status(t("status.nothing_copy"), "error")
            return
        text = "\n".join(lines)
        self.clipboard_clear()
        self.clipboard_append(text)
        self.set_status(t("status.copied", n=len(lines)), "ok")

    def _selected_rows_in_order(self, tree, selected: set) -> list[str]:
        """按树的显示顺序展开选中项。父/分组节点展开为其全部叶子后代（不含标题行）。"""
        out: list[str] = []

        def walk(parent: str, inherit: bool) -> None:
            for iid in tree.get_children(parent):
                kids = tree.get_children(iid)
                picked = inherit or (iid in selected)
                if picked and not kids and "group_other" not in tree.item(iid, "tags"):
                    out.append(iid)
                if kids:
                    walk(iid, picked)

        walk("", False)
        return out

    def _iter_tree_iids(self, tree, parent: str):
        """深度优先遍历当前显示的行（含展开/折叠的子节点）。"""
        for iid in tree.get_children(parent):
            yield iid
            yield from self._iter_tree_iids(tree, iid)

    @staticmethod
    def _row_to_text(tree, iid: str) -> str:
        """一行 → 一行文本。列表表格用制表符连接各列；树形表格取显示文本。"""
        item = tree.item(iid)
        values = item.get("values") or ()
        if values:
            return "\t".join(str(v) for v in values)
        return str(item.get("text") or "")

    # ------------------------------------------------------------ 渲染

    def _clear_tab(self, key: str) -> None:
        page = self._page(key)
        for w in page.winfo_children():
            w.destroy()

    def _placeholder(self, key: str, text: str | None = None) -> None:
        page = self._page(key)
        label = ctk.CTkLabel(page, text=text or t("common.none"),
                             text_color="gray", font=self.font_normal)
        label.pack(fill="both", expand=True)

    def clear_view(self) -> None:
        for key in _TAB_KEYS:
            self._clear_tab(key)
            self._placeholder(key)

    def render(self, report) -> None:
        self._render_info(report)
        self._render_debug(report)
        self._render_sections(report)
        self._render_imports(report)
        self._render_exports(report)
        self._render_risky_apis(report)
        self._render_strings(report)

    def _signature_text(self, report) -> str:
        sig = getattr(report, "signature", None)
        if not sig or not getattr(sig, "present", False):
            return t("signature.none")
        status = getattr(sig, "status", "unknown")
        key = {"valid": "signature.valid",
               "invalid": "signature.invalid"}.get(status, "signature.unknown")
        text = t(key)
        signer = getattr(sig, "signer", "")
        if signer:
            text += f" · {t('signature.signer')}: {signer}"
        return text

    def _render_info(self, report) -> None:
        key = "tab.basic"
        self._clear_tab(key)
        page = self._page(key)
        frame = ctk.CTkScrollableFrame(page, fg_color="transparent")
        frame.pack(fill="both", expand=True, padx=4, pady=4)
        frame.grid_columnconfigure(1, weight=1)

        packers = getattr(report, "packers", None) or []
        packer_text = (", ".join(getattr(p, "name", "") for p in packers)
                       if packers else t("packer.none"))

        rows = [
            (t("info.file"), report.path),
            (t("info.size"), human_size(report.file_size)),
            (t("info.format"), report.kind),
            (t("info.machine"), f"{report.machine_name}（{report.machine_zh}）"),
            (t("info.subsystem"), f"{report.subsystem_name}（{report.subsystem_zh}）"),
            (t("info.compile_time"), report.compile_time_text),
            (t("info.entry_point"), f"0x{report.entry_point_rva:08X}"),
            (t("info.image_base"), f"0x{report.image_base:016X}"),
            (t("info.sections_count"), str(report.num_sections)),
            (t("info.checksum"), f"0x{report.checksum:08X}"),
            (t("info.data_dirs"), t("info.unit_items", n=report.num_data_directories)),
            (t("info.bits"), t("info.unit_bits", n=report.bits)),
            (t("packer.title"), packer_text),
            (t("signature.title"), self._signature_text(report)),
        ]
        for i, (k, v) in enumerate(rows):
            ctk.CTkLabel(frame, text=k, text_color="gray", font=self.font_normal,
                         anchor="w").grid(row=i, column=0, sticky="w", padx=(12, 8), pady=3)
            ctk.CTkLabel(frame, text=v, font=self.font_normal,
                         anchor="w").grid(row=i, column=1, sticky="w", padx=(0, 12), pady=3)

        row = len(rows)
        if report.suspicious_sections:
            ctk.CTkLabel(frame, text=t("warn.high_entropy"),
                         text_color="#d13438", font=self.font_title, anchor="w").grid(
                row=row, column=0, columnspan=2, sticky="w", padx=12, pady=(8, 4))
            row += 1
        for w in report.warnings:
            ctk.CTkLabel(frame, text=t("warn.prefix", text=w), text_color="#d13438",
                         font=self.font_normal, anchor="w").grid(
                row=row, column=0, columnspan=2, sticky="w", padx=12, pady=2)
            row += 1

    def _render_debug(self, report) -> None:
        """渲染「调试信息」分页（A4）：调试目录条目表 + 顶部语义提示。

        三种情形：无调试目录 → 占位；有目录但无可用 PDB 路径 → 灰字提示；
        检测到 PDB 路径 → 红字提示（可能泄露编译机信息）。
        """
        key = "debug.tab"
        self._clear_tab(key)
        page = self._page(key)
        entries = getattr(report, "debug_entries", None) or []
        if not entries:
            self._placeholder(key, t("debug.none"))
            return

        if getattr(report, "has_pdb", False):
            head_text, head_color = t("debug.pdb_hint"), "#d13438"
        else:
            head_text, head_color = t("debug.no_pdb"), "gray"
        ctk.CTkLabel(page, text=head_text, font=self.font_normal,
                     anchor="w", text_color=head_color).pack(fill="x", padx=12, pady=(8, 0))
        ctk.CTkLabel(page, text=t("debug.summary", n=len(entries)), font=self.font_normal,
                     anchor="w", text_color="gray").pack(fill="x", padx=12, pady=(2, 0))

        search_var, count_label = self._build_search_bar(page)

        cols = ("type", "path", "name", "guid", "age", "cv")
        tree = ttk.Treeview(page, columns=cols, show="headings", style="PE.Treeview")
        for col, text, width, anchor in [
            ("type", t("debug.type"), 160, "w"),
            ("path", t("debug.pdb_path"), 420, "w"),
            ("name", t("debug.pdb_name"), 140, "w"),
            ("guid", t("debug.guid"), 280, "w"),
            ("age", t("debug.age"), 60, "e"),
            ("cv", t("debug.cv_signature"), 90, "w"),
        ]:
            tree.heading(col, text=text)
            tree.column(col, width=width, anchor=anchor, stretch=True)

        # 直接用 DebugInfo 原始值；空值统一显示 "-"（与其它分页的占位风格一致）
        rows = [
            _Row(None, "", (
                d.type_zh,
                d.pdb_path or "-",
                d.pdb_name or "-",
                d.guid or "-",
                str(d.age) if d.age else "-",
                d.cv_signature or "-",
            ), (), False)
            for d in entries
        ]
        self._attach_table(page, tree, rows, search_var, count_label)

    def _render_packers(self, report) -> None:
        """（预留）单独展示打包器证据；当前并入基本信息页。"""
        return

    def _render_sections(self, report) -> None:
        key = "tab.sections"
        self._clear_tab(key)
        page = self._page(key)

        # A5：属性异常的节区汇总提示（有问题才显示）
        if report.suspicious_section_count:
            head = ctk.CTkLabel(
                page,
                text=t("sections.suspect_summary", n=report.suspicious_section_count),
                font=self.font_normal, anchor="w", text_color="#d13438")
            head.pack(fill="x", padx=12, pady=(8, 0))

        search_var, count_label = self._build_search_bar(page)

        cols = ("name", "vsize", "rsize", "entropy", "perms", "perms_zh", "flag", "reasons")
        tree = ttk.Treeview(page, columns=cols, show="headings", style="PE.Treeview")
        for col, text, width, anchor in [
            ("name", t("sections.col_name"), 110, "w"),
            ("vsize", t("sections.col_vsize"), 85, "e"),
            ("rsize", t("sections.col_rsize"), 85, "e"),
            ("entropy", t("sections.col_entropy"), 60, "e"),
            ("perms", t("sections.col_perms"), 90, "w"),
            ("perms_zh", t("sections.col_meaning"), 180, "w"),
            ("flag", t("sections.col_flag"), 130, "w"),
            ("reasons", t("sections.col_reasons"), 260, "w"),
        ]:
            tree.heading(col, text=text)
            tree.column(col, width=width, anchor=anchor, stretch=True)
        # tag 注册：suspect 行用红色（疑似加壳节区）
        tree.tag_configure("suspect", foreground="#d13438")

        rows = [
            _Row(
                None, "",
                (s.name, human_size(s.virtual_size), human_size(s.raw_size),
                 f"{s.entropy:.2f}", s.perms, s.perms_zh,
                 t("sections.suspect") if s.is_suspicious else "",
                 t("common.reason_join").join(s.suspicious_reasons)),
                ("suspect",) if (s.is_suspicious or s.suspicious_reasons) else (),
                False,
            )
            for s in report.sections
        ]
        self._attach_table(page, tree, rows, search_var, count_label)

    def _render_imports(self, report) -> None:
        key = "tab.imports"
        self._clear_tab(key)
        page = self._page(key)
        if not report.has_imports:
            self._placeholder(key, t("common.no_imports"))
            return

        # 函数名(小写) → (等级, 分类)，用于给每个导入函数着色
        risk_map: dict[str, tuple[str, str]] = {}
        for x in report.risky_imports:
            risk_map[x.function.lower()] = (x.risk_level, x.category)

        total = sum(len(d.symbols) for d in report.imports)
        by_level = {lv: 0 for lv in RISK_COLORS}
        for x in report.risky_imports:
            by_level[x.risk_level] = by_level.get(x.risk_level, 0) + 1
        head = ctk.CTkLabel(
            page,
            text=t("imports.summary", ndll=len(report.imports), nfun=total,
                   crit=by_level["严重"], med=by_level["中等"], low=by_level["低"],
                   safe=total - len(report.risky_imports)),
            font=self.font_normal, anchor="w",
        )
        head.pack(fill="x", padx=12, pady=(8, 2))
        search_var, count_label = self._build_search_bar(page)

        tree = ttk.Treeview(page, show="tree", style="PE.Treeview")
        # 不随视口压缩：函数名过长时靠横向滚动条看完整内容
        tree.column("#0", width=900, minwidth=300, stretch=False)
        for level, color in RISK_COLORS.items():
            tree.tag_configure(f"risk_{level}", foreground=color)

        rows: list[_Row] = []
        for dll in report.imports:
            # DLL 父节点取旗下函数的"最高风险"，严重者默认展开
            dll_level = "安全"
            for sym in dll.symbols:
                lv = risk_map.get(sym.display.lower(), ("安全", ""))[0]
                if RISK_RANK.get(lv, 0) > RISK_RANK.get(dll_level, 0):
                    dll_level = lv
            n_bad = sum(1 for s in dll.symbols if s.display.lower() in risk_map)
            node_text = t("imports.dll_node", dll=dll.dll, n=len(dll.symbols), bad=n_bad)
            meaning = getattr(dll, "meaning", "")
            if meaning:
                node_text += f"  — {meaning}"
            parent = len(rows)
            rows.append(_Row(
                None, node_text, (), (f"risk_{dll_level}",), dll_level == "严重",
            ))
            for sym in dll.symbols:
                info = risk_map.get(sym.display.lower())
                if info:
                    lv, cat = info
                    text = f"{sym.display}    [{t(f'risk.{lv}', default=lv)}] {translate('RISK_CATEGORY', cat, default=cat)}"
                else:
                    lv, text = "安全", sym.display
                rows.append(_Row(parent, text, (), (f"risk_{lv}",), False))

        self._attach_table(page, tree, rows, search_var, count_label, is_tree=True)

    def _render_exports(self, report) -> None:
        key = "tab.exports"
        self._clear_tab(key)
        page = self._page(key)
        if not report.has_exports:
            self._placeholder(key, t("common.no_exports"))
            return

        search_var, count_label = self._build_search_bar(page)

        cols = ("ordinal", "rva", "name", "fwd")
        tree = ttk.Treeview(page, columns=cols, show="headings", style="PE.Treeview")
        for col, text, width, anchor in [
            ("ordinal", t("exports.col_ordinal"), 70, "e"),
            ("rva", t("exports.col_rva"), 100, "e"),
            ("name", t("exports.col_name"), 280, "w"),
            ("fwd", t("exports.col_forward"), 320, "w"),
        ]:
            tree.heading(col, text=text)
            tree.column(col, width=width, anchor=anchor, stretch=True)
        tree.column("fwd", stretch=False, minwidth=120)

        rows = [
            _Row(None, "", (sym.ordinal, f"0x{sym.rva:08X}",
                            sym.name or t("exports.ordinal_only"), sym.forwarder or ""), (), False)
            for sym in report.exports
        ]
        self._attach_table(page, tree, rows, search_var, count_label)

    def _render_risky_apis(self, report) -> None:
        key = "tab.risks"
        self._clear_tab(key)
        page = self._page(key)
        if not report.has_risky_imports:
            self._placeholder(key, t("common.no_risky"))
            return

        count_by_level = {"严重": 0, "中等": 0, "低": 0}
        for r in report.risky_imports:
            count_by_level[r.risk_level] = count_by_level.get(r.risk_level, 0) + 1
        head = ctk.CTkLabel(
            page,
            text=t("risks.summary", n=len(report.risky_imports),
                   crit=count_by_level["严重"], med=count_by_level["中等"], low=count_by_level["低"]),
            font=self.font_normal, anchor="w")
        head.pack(fill="x", padx=12, pady=(8, 2))
        search_var, count_label = self._build_search_bar(page)

        cols = ("dll", "function", "category", "risk", "desc")
        tree = ttk.Treeview(page, columns=cols, show="headings", style="PE.Treeview")
        for col, text, width, anchor in [
            ("dll", t("risks.col_dll"), 180, "w"),
            ("function", t("risks.col_function"), 220, "w"),
            ("category", t("risks.col_category"), 110, "w"),
            ("risk", t("risks.col_risk"), 80, "center"),
            ("desc", t("risks.col_desc"), 560, "w"),
        ]:
            tree.heading(col, text=text)
            tree.column(col, width=width, anchor=anchor, stretch=True)
        tree.column("desc", stretch=False, minwidth=160)

        for level, color in RISK_COLORS.items():
            tree.tag_configure(f"risk_{level}", foreground=color)

        rows = [
            _Row(None, "", (r.dll, r.function,
                            translate("RISK_CATEGORY", r.category, default=r.category),
                            t(f"risk.{r.risk_level}", default=r.risk_level),
                            r.description),
                 (f"risk_{r.risk_level}",), False)
            for r in report.risky_imports
        ]
        self._attach_table(page, tree, rows, search_var, count_label)

    def _render_strings(self, report) -> None:
        """渲染「字符串」分页：树形分组（父节点=分类，子节点=具体字符串）。"""
        key = "tab.strings"
        self._clear_tab(key)
        page = self._page(key)
        classes = report.string_classes or {}
        summary = report.strings_summary or {}

        if not report.string_count:
            self._placeholder(key, t("common.no_strings"))
            return

        ok = summary.get("external_ok")
        ext = t("strings.ext_ok") if ok else t("strings.ext_fail")
        counts = " / ".join(
            f"{t('strcls.' + k)} {len(classes.get(k) or [])}" for k in _STRING_CLASS_KEYS
        )
        head = ctk.CTkLabel(
            page,
            text=t("strings.summary", source=summary.get("source", "?"), ext=ext,
                   n=report.string_count, counts=counts),
            font=self.font_normal, anchor="w")
        head.pack(fill="x", padx=12, pady=(8, 2))
        search_var, count_label = self._build_search_bar(page)

        tree = ttk.Treeview(page, show="tree", style="PE.Treeview")
        tree.column("#0", width=1600, minwidth=300, stretch=False)
        for level, color in RISK_COLORS.items():
            tree.tag_configure(f"risk_{level}", foreground=color)
        tree.tag_configure("group_other", foreground="#9a9a9a")

        rows: list[_Row] = []
        for k in _STRING_CLASS_KEYS:
            label = t(f"strcls.{k}")
            values = classes.get(k) or []
            if not values:  # 命中 0 条的分类不显示，避免一堆空分组
                continue
            tag = ("group_other",) if k == "others" else ("risk_安全",)
            parent = len(rows)
            rows.append(_Row(None, f"{label} ({len(values)})", (), tag, k != "others"))
            shown = values[:STRING_OTHERS_LIMIT]
            for value in shown:
                rows.append(_Row(parent, value, (), (), False))
            hidden = len(values) - len(shown)
            if hidden > 0:
                rows.append(_Row(parent, t("strings.truncated", n=hidden), (), ("group_other",), False))

        self._attach_table(page, tree, rows, search_var, count_label, is_tree=True)

    def set_status(self, text: str, kind: str = "idle") -> None:
        color = STATUS_COLORS.get(kind, STATUS_COLORS["idle"])
        try:
            self.status_label.configure(text=text, text_color=color)
        except Exception:
            pass


# --------------------------------------------------------------------------
# 模块级入口
# --------------------------------------------------------------------------

def run_gui(preload: str | None = None) -> int:
    """启动图形界面，返回退出码（正常退出返回 0）。"""
    ctk.set_appearance_mode("system")
    ctk.set_default_color_theme("blue")

    try:
        root = MainWindow()
    except Exception as exc:  # 建窗失败也要可见（打包后无控制台）
        _log_exception(type(exc), exc, exc.__traceback__)
        try:
            messagebox.showerror(t("dlg.init_failed"), t("dlg.init_failed_msg", msg=exc))
        except Exception:
            pass
        return 1

    root.report_callback_exception = _make_exception_handler(root)

    if preload:
        root.path_var.set(preload)
        root.after(0, root._on_analyze)

    root.mainloop()
    return 0
