"""GUI 单元 / 集成测试（纯函数 + 受控渲染）。

运行：.venv/Scripts/python.exe -m unittest tests.test_gui -v
无图形界面时，集成用例会自动跳过（pytest 风格的 skip 通过 try/except 实现）。
"""
from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ui import gui as gui_mod
from ui.gui import (  # noqa: E402
    _filter_rows,
    _log_path,
    _make_exception_handler,
    _row_hit,
    _Row,
    parse_dropped_files,
)

# 真实样本（仓库自带）
KERNEL32 = str(ROOT / "test" / "01_kernel32.dll")
MSHTML = str(ROOT / "test" / "15_mshtml.dll_32bit")


class TestParseDroppedFiles(unittest.TestCase):
    """拖放路径解析（Windows 含空格路径 + 多文件）。"""

    def test_single_plain(self):
        self.assertEqual(parse_dropped_files("C:\\a\\b.exe"), ["C:\\a\\b.exe"])

    def test_space_wrapped_in_braces(self):
        self.assertEqual(
            parse_dropped_files("{C:\\Program Files\\x y\\a b.exe}"),
            ["C:\\Program Files\\x y\\a b.exe"],
        )

    def test_multiple_space_separated(self):
        got = parse_dropped_files(
            "{C:\\Program Files\\a.exe} D:\\b.exe"
        )
        self.assertEqual(got, ["C:\\Program Files\\a.exe", "D:\\b.exe"])

    def test_trailing_buffer_flushed(self):
        self.assertEqual(parse_dropped_files("D:\\x.exe "), ["D:\\x.exe"])

    def test_quotes_stripped(self):
        self.assertEqual(parse_dropped_files('"D:\\x.exe"'), ["D:\\x.exe"])

    def test_empty(self):
        self.assertEqual(parse_dropped_files(""), [])
        self.assertEqual(parse_dropped_files(None), [])


class TestRowFilter(unittest.TestCase):
    """搜索过滤逻辑（列表表格 + 树形表格）。"""

    def test_row_hit_case_insensitive(self):
        row = _Row(None, "KERNEL32", ("CreateFile", "0x1000"), (), False)
        self.assertTrue(_row_hit(row, "kernel32"))
        self.assertTrue(_row_hit(row, "createfile"))
        self.assertFalse(_row_hit(row, "zzz"))

    def test_filter_list_all_when_empty_keyword(self):
        rows = [_Row(None, "a", ("x",), (), False),
                _Row(None, "b", ("y",), (), False)]
        self.assertEqual(_filter_rows(rows, "", False), {0, 1})

    def test_filter_list_partial(self):
        rows = [_Row(None, "abc", ("1",), (), False),
                _Row(None, "xyz", ("2",), (), False)]
        self.assertEqual(_filter_rows(rows, "abc", False), {0})

    def test_filter_tree_parent_hit_shows_children(self):
        # 父 0，子 1/2
        rows = [
            _Row(None, "KERNEL32", (), (), False),
            _Row(0, "CreateFile", (), (), False),
            _Row(0, "ReadFile", (), (), False),
        ]
        shown = _filter_rows(rows, "kernel32", True)
        self.assertEqual(shown, {0, 1, 2})

    def test_filter_tree_child_hit_shows_parent(self):
        rows = [
            _Row(None, "KERNEL32", (), (), False),
            _Row(0, "CreateFile", (), (), False),
            _Row(0, "ReadFile", (), (), False),
        ]
        shown = _filter_rows(rows, "readfile", True)
        self.assertEqual(shown, {0, 2})


class TestLogPath(unittest.TestCase):
    """日志路径落在 LOCALAPPDATA，绝不写 cwd。"""

    def test_is_path_under_peinspector(self):
        p = _log_path()
        self.assertIsInstance(p, Path)
        self.assertIn("PEInspector", str(p))
        # 不应落在当前工作目录
        self.assertNotEqual(p.parent, Path.cwd())


class TestExceptionHandler(unittest.TestCase):
    def test_returns_callable_and_does_not_raise(self):
        handler = _make_exception_handler(None)
        self.assertTrue(callable(handler))
        # 调用不应抛异常（messagebox 失败已被内部 try 吞掉）
        try:
            handler(ValueError, ValueError("boom"), None)
        except Exception as exc:  # pragma: no cover
            self.fail(f"handler raised: {exc}")


class TestSignatureText(unittest.TestCase):
    """MainWindow._signature_text 对真实报告不抛异常（不依赖显示，按未绑定调用）。"""

    def test_kernel32(self):
        from achieve.pe_parser import parse_pe
        r = parse_pe(KERNEL32)
        # _signature_text 仅用 t() 与 getattr(report.signature)，不触碰 widget
        text = gui_mod.MainWindow._signature_text(None, r)
        self.assertIsInstance(text, str)
        self.assertTrue(text)


class TestApplyTreeviewTheme(unittest.TestCase):
    """主题取色配置不抛异常。"""

    def test_configure_ok(self):
        import tkinter as tk
        import tkinter.ttk as ttk
        try:
            root = tk.Tk()
            root.withdraw()
            style = ttk.Style(root)
            gui_mod.apply_treeview_theme(style)
            self.assertTrue(True)
        finally:
            try:
                root.destroy()
            except Exception:
                pass


class TestGuiIntegration(unittest.TestCase):
    """受控集成：构造主窗口、解析样本、渲染、校验行数。

    无显示环境时整体跳过。
    """

    @classmethod
    def setUpClass(cls):
        try:
            import tkinter as tk
            tk.Tk().destroy()  # 探测是否有显示
            cls._has_display = True
        except Exception:
            cls._has_display = False

    def _make_window(self):
        from ui.gui import MainWindow
        w = MainWindow()
        w.update_idletasks()
        return w

    def test_render_sections_row_count(self):
        if not self._has_display:
            self.skipTest("no display available")
        from achieve.pe_parser import parse_pe
        r = parse_pe(KERNEL32)
        w = self._make_window()
        try:
            w.render(r)
            # 节区分页里的 Treeview 行数应等于 len(sections)
            page = w._page("tab.sections")
            tree = None
            for child in page.winfo_children():
                if isinstance(child, __import__("tkinter.ttk").ttk.Treeview):
                    tree = child
                    break
            self.assertIsNotNone(tree, "sections tree not found")
            self.assertEqual(len(tree.get_children()), len(r.sections))
        finally:
            w.destroy()

    def test_render_full_no_exception(self):
        if not self._has_display:
            self.skipTest("no display available")
        from achieve.pe_parser import parse_pe
        r = parse_pe(MSHTML, lang="en")
        w = self._make_window()
        try:
            w.render(r)
            self.assertEqual(w._report, None)  # render 不缓存报告
        finally:
            w.destroy()


if __name__ == "__main__":
    unittest.main(verbosity=2)
