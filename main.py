"""Windows PE Inspector —— 图形界面入口。

纯静态解析 PE 文件，绝不加载、绝不运行样本。
双击本文件（或编译后的 exe）即可启动图形界面；命令行解析请用 cmd_main.py。
"""

import sys

from ui.gui import run_gui


if __name__ == "__main__":
    sys.exit(run_gui())
