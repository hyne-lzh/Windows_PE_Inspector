"""Windows PE Inspector —— 图形界面入口。

纯静态解析 PE 文件，绝不加载、绝不运行样本。
双击本文件（或编译后的 exe）即可启动图形界面；命令行解析请用 cmd_main.py。
"""

import sys


def _fatal(title: str, msg: str) -> int:
    """启动期致命错误：写日志 + 原生弹窗（打包后无控制台，必须界面可见）。"""
    try:
        from ui.gui import _log_exception
        _log_exception(RuntimeError, RuntimeError(msg), None)
    except Exception:
        pass
    try:
        import tkinter as tk
        from tkinter import messagebox
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror(title, msg)
        root.destroy()
    except Exception:
        pass
    try:
        sys.stderr.write(f"{title}: {msg}\n")
    except Exception:
        pass
    return 1


def main() -> int:
    # P1-5：依赖缺失必须给出可见提示，而不是让 exe 静默闪退。
    try:
        from ui.gui import run_gui
    except ImportError as exc:
        return _fatal(
            "Windows PE Inspector 启动失败",
            f"缺少运行依赖：{exc}\n\n请先安装依赖：pip install -r requirements.txt",
        )
    return run_gui()


if __name__ == "__main__":
    sys.exit(main())
