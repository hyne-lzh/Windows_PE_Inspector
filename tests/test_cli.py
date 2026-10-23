"""CLI 单元 / 集成测试（渲染函数 + 子进程退出码）。

运行：.venv/Scripts/python.exe -m unittest tests.test_cli -v
"""
from __future__ import annotations

import contextlib
import io
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import cli.cli as cli_mod
from achieve.pe_parser import parse_pe

KERNEL32 = str(ROOT / "test" / "01_kernel32.dll")
MSHTML = str(ROOT / "test" / "15_mshtml.dll_32bit")
CMD_MAIN = str(ROOT / "cmd_main.py")
PY = sys.executable


def _run_report(show_func, report) -> str:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        show_func(report)
    return buf.getvalue()


class TestCliRender(unittest.TestCase):
    """各 show_* 渲染函数不抛异常且含关键字段。"""

    def test_header(self):
        r = parse_pe(KERNEL32)
        out = _run_report(cli_mod.show_header, r)
        self.assertIn(r.path, out)
        self.assertIn("基本信息", out)
        self.assertIn(str(r.num_sections), out)

    def test_sections(self):
        r = parse_pe(KERNEL32)
        out = _run_report(cli_mod.show_sections, r)
        self.assertIn("节区", out)
        self.assertTrue(len(r.sections) > 0)

    def test_imports(self):
        r = parse_pe(KERNEL32)
        out = _run_report(cli_mod.show_imports, r)
        self.assertIn("导入表", out)          # 区块标题
        self.assertIn("DLL", out)             # 导入汇总行（zh "个 DLL" / en "DLLs"）
        # kernel32 自身是被导入方，其依赖来自 ntdll / api-ms 等
        self.assertTrue("ntdll" in out or "api-ms" in out or "KernelBase" in out)

    def test_exports_may_be_empty(self):
        # 找到第一个"无导出"的样本来校验空态文案
        no_export = None
        for name in sorted(os.listdir(str(ROOT / "test"))):
            p = str(ROOT / "test" / name)
            if os.path.isfile(p) and p.lower().endswith((".exe", ".dll", ".sys")):
                try:
                    rr = parse_pe(p)
                except Exception:
                    continue
                if not rr.has_exports:
                    no_export = rr
                    break
        self.assertIsNotNone(no_export, "未找到无导出样本")
        out = _run_report(cli_mod.show_exports, no_export)
        self.assertIn("无导出", out)

    def test_risks_or_none(self):
        # 360Sensor 含高危 API；若样本无风险，应显示"无"
        r = parse_pe(str(ROOT / "test" / "07_360Sensor64.sys"))
        out = _run_report(cli_mod.show_risks, r)
        self.assertTrue("高危" in out or "无" in out)

    def test_packers(self):
        r = parse_pe(KERNEL32)
        out = _run_report(cli_mod.show_packers, r)
        self.assertTrue(len(out) > 0)

    def test_signature(self):
        r = parse_pe(KERNEL32)
        out = _run_report(cli_mod.show_signature, r)
        self.assertTrue(len(out) > 0)

    def test_debug(self):
        r = parse_pe(KERNEL32)
        out = _run_report(cli_mod.show_debug, r)
        self.assertTrue(len(out) > 0)

    def test_strings(self):
        r = parse_pe(KERNEL32)
        out = _run_report(cli_mod.show_strings, r)
        self.assertTrue(len(out) > 0)

    def test_all_renders_english_no_exception(self):
        r = parse_pe(MSHTML, lang="en")
        for fn in (cli_mod.show_header, cli_mod.show_sections,
                   cli_mod.show_imports, cli_mod.show_exports,
                   cli_mod.show_risks, cli_mod.show_packers,
                   cli_mod.show_signature, cli_mod.show_debug,
                   cli_mod.show_strings):
            try:
                _run_report(fn, r)
            except Exception as exc:  # pragma: no cover
                self.fail(f"{fn.__name__} raised in en: {exc}")


class TestCliSubprocess(unittest.TestCase):
    """cmd_main.py 子进程：退出码与关键输出。"""

    def _call(self, *args):
        return subprocess.run(
            [PY, CMD_MAIN, *args],
            cwd=str(ROOT), capture_output=True, text=True,
            env={**os.environ, "PYTHONIOENCODING": "utf-8"},
        )

    def test_version(self):
        res = self._call("--version")
        self.assertEqual(res.returncode, 0)
        self.assertIn("Windows PE Inspector", res.stdout)

    def test_header_valid(self):
        res = self._call(KERNEL32, "--header")
        self.assertEqual(res.returncode, 0)
        self.assertIn("基本信息", res.stdout)

    def test_missing_file_exit_1(self):
        res = self._call(str(ROOT / "test" / "no_such_file.exe"))
        self.assertEqual(res.returncode, 1)

    def test_bad_pe_exit_2(self):
        with tempfile.NamedTemporaryFile("w", suffix=".dll", delete=False) as fh:
            fh.write("this is not a PE file at all\n")
            bad = fh.name
        try:
            res = self._call(bad)
            self.assertEqual(res.returncode, 2)
        finally:
            os.unlink(bad)

    def test_export_only_suppresses_display(self):
        """G5：单独 --export 时不打印基本信息（当前设计）。

        该用例固化当前行为；若按 G5 建议改为"既显示又导出"，需同步更新本断言。
        """
        with tempfile.TemporaryDirectory() as td:
            out = os.path.join(td, "r.html")
            res = self._call(KERNEL32, "--export", out)
            self.assertEqual(res.returncode, 0)
            self.assertNotIn("基本信息", res.stdout)


class TestTruncationConsistency(unittest.TestCase):
    """G2：截断 PE 节区"声明数≠实际数"，表现层未告警（已知缺口）。

    用此用例固化现象；核心层/表现层修复后，应改为断言二者一致。
    """

    def _trunc(self, n: int) -> str:
        data = Path(KERNEL32).read_bytes()[:n]
        fd, p = tempfile.mkstemp(suffix=".dll")
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        return p

    def test_normal_file_consistent(self):
        r = parse_pe(KERNEL32)
        self.assertEqual(r.num_sections, len(r.sections))

    def test_truncated_inconsistent(self):
        p = self._trunc(512)
        try:
            r = parse_pe(p)
            # 声明 8 节区，实际 0 可解析 —— 已知不一致（G2）
            self.assertNotEqual(r.num_sections, len(r.sections))
            self.assertEqual(len(r.sections), 0)
            self.assertEqual(len(r.warnings), 0)  # 无任何告警
        finally:
            os.unlink(p)


if __name__ == "__main__":
    unittest.main(verbosity=2)
