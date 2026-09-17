"""Windows PE Inspector —— 命令行入口。

纯静态解析 PE 文件（exe / dll / sys），打印结构信息；绝不加载/运行样本。
用法见 achieve/cli.py 的 argparse 说明；图形界面入口是 main.py。
"""

import sys

from cli.cli import main


if __name__ == "__main__":
    sys.exit(main())
