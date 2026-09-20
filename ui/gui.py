"""Windows PE Inspector —— 图形界面（customtkinter）。

选一个 PE 文件 → 后台线程解析 → 四页展示（基本信息 / 节区 / 导入表 / 导出表）。
线程模型（铁律，不得更改）：
- 解析跑在 ``threading.Thread(daemon=True)`` 里，**绝不触碰任何 widget**；
- 工作线程只通过 ``self._queue`` 回传 ``("ok", report)`` 或 ``("err", 中文文案)``；
- 主线程用 ``self.after(100, self._poll)`` 轮询队列并更新界面。

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

import customtkinter as ctk

from achieve.pe_parser import PeParseError, human_size, parse_pe

# --------------------------------------------------------------------------
# 全局常量
# --------------------------------------------------------------------------

TITLE = "Windows PE Inspector"
WINDOW_W = 1020
WINDOW_H = 680
MIN_W = 880
MIN_H = 560

FONT_FAMILY = "Microsoft YaHei UI"  # 本机已实测可用；不带 UI 的 "Microsoft YaHei" 不存在

TAB_NAMES = ("基本信息", "节区", "导入表", "导出表", "高危 API")

# 高危 API 等级 → 颜色（用于 tag 着色）
RISK_COLORS = {
    "严重": "#d13438",   # 红
    "中等": "#e0883a",   # 橙
    "低":   "#888",        # 灰
}
PLACEHOLDER_TEXT = "尚未选择文件"

# 状态栏配色：灰色 / 蓝色 / 绿色 / 红色
STATUS_COLORS = {
    "idle": "#9a9a9a",
    "busy": "#3b8ed0",
    "ok": "#2fa572",
    "error": "#d13438",
}


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
                "发生未处理的异常",
                f"程序遇到未处理的异常，详情已写入日志：\n{_log_path()}\n\n"
                f"{exc_type.__name__}: {exc_val}",
            )
        except Exception:
            pass

    return handler


# --------------------------------------------------------------------------
# 主题取色（让 ttk.Treeview 尽量贴合 customtkinter 当前主题）
# --------------------------------------------------------------------------

def apply_treeview_theme(style: ttk.Style) -> None:
    """在已创建的 ttk.Style 上配置 PE.Treeview 主题色（主窗口 __init__ 调用一次，渲染时不再重配）。"""
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

class MainWindow(ctk.CTk):
    """应用主窗口。"""

    def __init__(self) -> None:
        ctk.set_appearance_mode("system")
        ctk.set_default_color_theme("blue")

        super().__init__()

        self.title(TITLE)
        self.minsize(MIN_W, MIN_H)
        self._center_window()

        self.font_normal = ctk.CTkFont(family=FONT_FAMILY, size=13)
        self.font_title = ctk.CTkFont(family=FONT_FAMILY, size=15, weight="bold")

        # ttk.Style 一次性创建；configure 每次渲染调用很轻，但避免反复创建 Style 实例
        self._style = ttk.Style(self)
        apply_treeview_theme(self._style)

        # 线程与队列（契约见模块 docstring）
        self._queue: queue.Queue = queue.Queue()
        self._worker: threading.Thread | None = None

        self._build_layout()
        self.clear_view()
        self.set_status("就绪", "idle")

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

        ctk.CTkLabel(bar, text="PE 文件", font=self.font_normal).grid(
            row=0, column=0, padx=(12, 8), pady=12)

        self.path_var = tk.StringVar()
        self.entry = ctk.CTkEntry(bar, textvariable=self.path_var, font=self.font_normal)
        self.entry.grid(row=0, column=1, sticky="ew", padx=(0, 8), pady=12)

        self.btn_browse = ctk.CTkButton(
            bar, text="浏览…", width=90, font=self.font_normal, command=self._browse)
        self.btn_browse.grid(row=0, column=2, padx=(0, 8), pady=12)

        self.btn_analyze = ctk.CTkButton(
            bar, text="开始分析", width=100, font=self.font_normal, command=self._on_analyze)
        self.btn_analyze.grid(row=0, column=3, padx=(0, 12), pady=12)

    def _build_tabs(self) -> None:
        # 注意：customtkinter 6.0.0 的 CTkTabview 不支持 font 参数（5.x 教程里才有）
        self.tabs = ctk.CTkTabview(self)
        self.tabs.grid(row=1, column=0, sticky="nsew", padx=12, pady=6)
        for name in TAB_NAMES:
            self.tabs.add(name)

    def _build_status_bar(self) -> None:
        bar = ctk.CTkFrame(self, corner_radius=0)
        bar.grid(row=2, column=0, sticky="ew", padx=12, pady=(6, 12))
        bar.grid_columnconfigure(0, weight=1)

        self.status_label = ctk.CTkLabel(bar, text="就绪", anchor="w", font=self.font_normal)
        self.status_label.grid(row=0, column=0, sticky="ew", padx=(12, 8), pady=8)

        self.progress = ctk.CTkProgressBar(bar, mode="indeterminate", width=160)
        self.progress.grid(row=0, column=1, padx=(0, 12), pady=8)
        self.progress.set(0)

    # ------------------------------------------------------------ 交互动作

    def _browse(self) -> None:
        path = filedialog.askopenfilename(
            title="选择 PE 文件",
            filetypes=[("PE 文件", "*.exe;*.dll;*.sys"), ("所有文件", "*.*")],
        )
        if path:
            self.path_var.set(path)

    def _on_analyze(self) -> None:
        if self._worker is not None and self._worker.is_alive():
            return
        path = self.path_var.get().strip()
        if not path:
            self.set_status("请先选择文件", "error")
            return

        self.clear_view()
        self.btn_analyze.configure(state="disabled")
        self.set_status("正在解析…", "busy")
        self.progress.start()

        self._worker = threading.Thread(target=self._run_parse, args=(path,), daemon=True)
        self._worker.start()
        self.after(100, self._poll)

    # ------------------------------------------------------------ 线程契约

    def _run_parse(self, path: str) -> None:
        """后台线程体：解析 PE 并回传结果。绝不触碰任何 widget。"""
        try:
            report = parse_pe(path)
            self._queue.put(("ok", report))
        except PeParseError as exc:
            self._queue.put(("err", str(exc)))
        except Exception as exc:  # noqa: BLE001
            self._queue.put(("err", f"解析时发生未预期错误：{type(exc).__name__}: {exc}"))

    def _poll(self) -> None:
        try:
            kind, payload = self._queue.get_nowait()
        except queue.Empty:
            worker = self._worker
            if worker is not None and not worker.is_alive():
                self._finish_busy()
                self.set_status("解析线程异常退出，未返回结果", "error")
                return
            self.after(100, self._poll)
            return

        self._finish_busy()
        if kind == "ok":
            self.render(payload)
            self.set_status(
                f"分析完成：{len(payload.sections)} 节区 / {len(payload.imports)} 个 DLL"
                f"{f' / {len(payload.risky_imports)} 高危 API' if payload.has_risky_imports else ''}",
                "ok",
            )
        else:
            self.clear_view()
            self.set_status(f"解析失败：{payload}", "error")
            try:
                messagebox.showerror("解析失败", payload)
            except Exception:
                pass

    def _finish_busy(self) -> None:
        self.progress.stop()
        self.progress.set(0)
        self.btn_analyze.configure(state="normal")
        self._worker = None

    # ------------------------------------------------------------ 渲染

    def _clear_tab(self, name: str) -> None:
        page = self.tabs.tab(name)
        for w in page.winfo_children():
            w.destroy()

    def _placeholder(self, name: str, text: str = PLACEHOLDER_TEXT) -> None:
        page = self.tabs.tab(name)
        label = ctk.CTkLabel(page, text=text, text_color="gray", font=self.font_normal)
        label.pack(fill="both", expand=True)

    def clear_view(self) -> None:
        for name in TAB_NAMES:
            self._clear_tab(name)
            self._placeholder(name)

    def render(self, report) -> None:
        self._render_info(report)
        self._render_sections(report)
        self._render_imports(report)
        self._render_exports(report)
        self._render_risky_apis(report)

    def _render_info(self, report) -> None:
        self._clear_tab("基本信息")
        page = self.tabs.tab("基本信息")
        frame = ctk.CTkScrollableFrame(page, fg_color="transparent")
        frame.pack(fill="both", expand=True, padx=4, pady=4)
        frame.grid_columnconfigure(1, weight=1)

        rows = [
            ("文件", report.path),
            ("大小", human_size(report.file_size)),
            ("格式", f"{report.kind}　架构 {report.machine_name}"),
            ("子系统", report.subsystem_name),
            ("编译时间", report.compile_time_text),
            ("入口点 RVA", f"0x{report.entry_point_rva:08X}"),
            ("镜像基址", f"0x{report.image_base:016X}"),
            ("节区数量", str(report.num_sections)),
            ("校验和", f"0x{report.checksum:08X}"),
            ("数据目录", f"{report.num_data_directories} 项"),
            ("位数", f"{report.bits} 位"),
        ]
        for i, (k, v) in enumerate(rows):
            ctk.CTkLabel(frame, text=k, text_color="gray", font=self.font_normal,
                         anchor="w").grid(row=i, column=0, sticky="w", padx=(12, 8), pady=3)
            ctk.CTkLabel(frame, text=v, font=self.font_normal,
                         anchor="w").grid(row=i, column=1, sticky="w", padx=(0, 12), pady=3)

        row = len(rows)
        if report.suspicious_sections:
            ctk.CTkLabel(frame, text="[!] 存在高熵节区：文件可能被加壳或加密",
                         text_color="#d13438", font=self.font_title, anchor="w").grid(
                row=row, column=0, columnspan=2, sticky="w", padx=12, pady=(8, 4))
            row += 1
        for w in report.warnings:
            ctk.CTkLabel(frame, text=f"[!] {w}", text_color="#d13438",
                         font=self.font_normal, anchor="w").grid(
                row=row, column=0, columnspan=2, sticky="w", padx=12, pady=2)
            row += 1

    def _render_sections(self, report) -> None:
        self._clear_tab("节区")
        page = self.tabs.tab("节区")

        cols = ("name", "vsize", "rsize", "entropy", "perms", "perms_zh", "flag")
        tree = ttk.Treeview(page, columns=cols, show="headings", style="PE.Treeview")
        for col, text, width, anchor in [
            ("name", "名称", 120, "w"),
            ("vsize", "虚拟大小", 90, "e"),
            ("rsize", "原始大小", 90, "e"),
            ("entropy", "熵值", 65, "e"),
            ("perms", "权限", 95, "w"),
            ("perms_zh", "含义", 200, "w"),
            ("flag", "标记", 150, "w"),
        ]:
            tree.heading(col, text=text)
            tree.column(col, width=width, anchor=anchor, stretch=True)
        # tag 注册：suspect 行用红色（疑似加壳节区）
        tree.tag_configure("suspect", foreground="#d13438")

        for s in report.sections:
            tree.insert(
                "", "end",
                values=(s.name, human_size(s.virtual_size), human_size(s.raw_size),
                        f"{s.entropy:.2f}", s.perms, s.perms_zh,
                        "疑似加壳/加密" if s.is_suspicious else ""),
                tags=("suspect",) if s.is_suspicious else (),
            )

        sb = ttk.Scrollbar(page, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=sb.set)
        tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

    def _render_imports(self, report) -> None:
        self._clear_tab("导入表")
        page = self.tabs.tab("导入表")
        if not report.has_imports:
            self._placeholder("导入表", "(无导入表)")
            return

        total = sum(len(d.symbols) for d in report.imports)
        head = ctk.CTkLabel(page, text=f"合计：{len(report.imports)} 个 DLL，{total} 个函数",
                            font=self.font_normal, anchor="w")
        head.pack(fill="x", padx=12, pady=(8, 2))

        tree = ttk.Treeview(page, show="tree", style="PE.Treeview")
        tree.column("#0", width=420, stretch=True)
        for dll in report.imports:
            node = tree.insert("", "end", text=f"{dll.dll}  ({len(dll.symbols)})", open=False)
            for sym in dll.symbols:
                tree.insert(node, "end", text=sym.display)

        sb = ttk.Scrollbar(page, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=sb.set)
        tree.pack(side="left", fill="both", expand=True, padx=(12, 0))
        sb.pack(side="right", fill="y")

    def _render_exports(self, report) -> None:
        self._clear_tab("导出表")
        page = self.tabs.tab("导出表")
        if not report.has_exports:
            self._placeholder("导出表", "(无导出表，通常说明这是可执行程序而非 DLL)")
            return

        cols = ("ordinal", "rva", "name", "fwd")
        tree = ttk.Treeview(page, columns=cols, show="headings", style="PE.Treeview")
        for col, text, width, anchor in [
            ("ordinal", "序号", 70, "e"),
            ("rva", "RVA", 100, "e"),
            ("name", "名称", 280, "w"),
            ("fwd", "转发目标", 220, "w"),
        ]:
            tree.heading(col, text=text)
            tree.column(col, width=width, anchor=anchor, stretch=True)

        for sym in report.exports:
            tree.insert("", "end", values=(
                sym.ordinal, f"0x{sym.rva:08X}", sym.name or "(仅序号)", sym.forwarder or ""))

        sb = ttk.Scrollbar(page, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=sb.set)
        tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

    def _render_risky_apis(self, report) -> None:
        self._clear_tab("高危 API")
        page = self.tabs.tab("高危 API")
        if not report.has_risky_imports:
            self._placeholder("高危 API", "[ok] 未匹配到高危 API")
            return

        # 顶部分级统计
        count_by_level = {"严重": 0, "中等": 0, "低": 0}
        for r in report.risky_imports:
            count_by_level[r.risk_level] = count_by_level.get(r.risk_level, 0) + 1
        head_text = (
            f"合计 {len(report.risky_imports)} 个高危 API"
            f"　严重 {count_by_level['严重']}　中等 {count_by_level['中等']}　低 {count_by_level['低']}"
        )
        head = ctk.CTkLabel(page, text=head_text, font=self.font_normal, anchor="w")
        head.pack(fill="x", padx=12, pady=(8, 2))

        cols = ("dll", "function", "category", "risk", "desc")
        tree = ttk.Treeview(page, columns=cols, show="headings", style="PE.Treeview")
        for col, text, width, anchor in [
            ("dll", "DLL", 180, "w"),
            ("function", "函数", 220, "w"),
            ("category", "分类", 100, "w"),
            ("risk", "等级", 70, "center"),
            ("desc", "说明", 360, "w"),
        ]:
            tree.heading(col, text=text)
            tree.column(col, width=width, anchor=anchor, stretch=True)

        # 风险等级 tag 注册（颜色按等级映射）
        for level, color in RISK_COLORS.items():
            tree.tag_configure(f"risk_{level}", foreground=color)

        for r in report.risky_imports:
            tree.insert(
                "", "end",
                values=(r.dll, r.function, r.category, r.risk_level, r.description),
                tags=(f"risk_{r.risk_level}",),
            )

        sb = ttk.Scrollbar(page, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=sb.set)
        tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

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
            messagebox.showerror("启动失败", f"无法创建主窗口：{exc}")
        except Exception:
            pass
        return 1

    root.report_callback_exception = _make_exception_handler(root)

    if preload:
        root.path_var.set(preload)
        root.after(0, root._on_analyze)

    root.mainloop()
    return 0
