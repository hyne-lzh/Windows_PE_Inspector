# Windows PE Inspector

![status](https://img.shields.io/badge/status-in%20progress-orange)
![python](https://img.shields.io/badge/python-3.12-blue)
![deps](https://img.shields.io/badge/dependencies-pefile%20%7C%20customtkinter-lightgrey)
![license](https://img.shields.io/badge/license-MIT-green)

> 一个用 Python 写的 Windows PE 文件静态分析工具：把 exe / dll 丢进来，看清它依赖了什么 DLL、是不是被加壳打包、有没有可疑行为——**全程不运行样本**，纯静态解析。

## 项目状态

**状态：开发中（In Progress）**

当前项目处于早期开发阶段：**工程环境已搭建完成，核心功能正在开发，暂无可运行的发布版本。**

| 模块 | 状态 | 说明 |
|------|------|------|
| 工程环境 | 已完成 | `.venv`（Python 3.12.8）、`requirements.txt`、`.gitignore` |
| 编译链路 | 已完成 | Nuitka 4.2.1 环境已就绪，编译参数已核实 |
| 解析原型 | 开发中 | 基于 `pefile` 解析 PE 结构，打印导入表 |
| 图形界面 | 规划中 | `customtkinter` 界面框架与窗口分区 |
| 信息面板 | 规划中 | 头信息、节区表、导入/导出表可视化 |
| 特色功能 | 规划中 | 加壳检测、依赖检测、打包器识别 |
| 报告导出 | 规划中 | Excel / HTML 分析报告 |
| 打包发布 | 规划中 | Nuitka 编译为免安装 exe |

> 进度会在本文件持续更新，每个阶段完成后同步状态。

## 这个工具要解决什么问题

1. **这个程序依赖了什么？** —— 想知道一个 exe 需要哪些 DLL、哪些运行库。
2. **为什么在别人电脑上打不开？** —— 排查缺失的运行库、32/64 位冲突等问题。
3. **这个文件是不是被加壳了？** —— 通过节区熵值判断是否被压缩或加密。
4. **它是用什么打包的？** —— 识别 PyInstaller、Nuitka、UPX 等常见打包器。
5. **这个文件可疑吗？** —— 静态匹配高危 API、可疑字符串，不运行样本即可初筛。

## 功能规划

### 已完成

- [x] 创建项目虚拟环境与依赖清单
- [x] 配置 Git 忽略规则（虚拟环境、打包产物、IDE 配置等）
- [x] 确定技术选型与 Nuitka 编译参数

### 开发中

- [ ] PE 文件解析核心（导入表解析已完成原型，正在整理为模块）

### 规划中

- [ ] 基础信息面板：架构位数、编译时间戳、入口点、校验和
- [ ] 节区表格：名称、大小、权限、熵值（异常节区高亮）
- [ ] 加壳检测：熵值超阈值时提示"疑似加壳"
- [ ] 导入 / 导出表：DLL 与函数层级树形展示
- [ ] 资源提取：图标导出 PNG、版本信息与公司名读取
- [ ] 高危 API 标记：内置敏感 API 词表匹配
- [ ] 字符串提取：URL、IP、注册表路径、文件路径
- [ ] DLL 依赖检测：检查系统是否存在、位数是否匹配、递归展开依赖树
- [ ] 打包器识别：PyInstaller / Nuitka / UPX / VMProtect（本项目自身也用 Nuitka 编译）
- [ ] 数字签名校验：判断是否为官方原版
- [ ] 批量扫描：整个目录一次分析，风险分级汇总
- [ ] 报告导出：Excel / HTML 格式分析报告
- [ ] 界面增强：文件拖拽、右键菜单、复制与搜索
- [ ] 打包发布：Nuitka 编译为无控制台窗口的 exe

## 技术栈

| 层次 | 选型 | 说明 |
|------|------|------|
| 语言 | Python 3.12 | 使用 Python 3.12.8 构建环境（**不要用 3.13+**，见编译说明） |
| PE 解析 | [pefile](https://github.com/erocarrera/pefile) | 成熟的 PE 文件解析库 |
| 图形界面 | [customtkinter](https://customtkinter.tomschimansky.com/) | 基于 tkinter 的现代化界面库，外观更现代 |
| 报告导出 | openpyxl | 导出 Excel 汇总表（待引入） |
| 编译 | [Nuitka](https://nuitka.net/) | 编译为原生机器码，体积更小、启动更快 |

**设计原则：依赖保持精简、精确锁版本，便于分发与编译。**

## 目录结构

```
Windows_PE_Inspector/
├── main.py                 # 程序入口（CLI / GUI 双入口）
├── core/                   # 解析核心
│   ├── pe_parser.py        # PE 结构解析
│   ├── dependency.py       # 依赖分析与缺失检测
│   ├── packer.py           # 加壳 / 打包器识别
│   └── report.py           # 报告导出
├── ui/                     # customtkinter 界面
│   ├── main_window.py      # 主窗口与布局
│   └── widgets.py          # 自定义控件
├── samples/                # 测试样本
├── md/                     # 说明文档
│   └── nuitka_install.md   # Nuitka 编译指南
├── requirements.txt        # 依赖清单
├── .gitignore
└── README.md
```

> 注：`core/`、`ui/`、`samples/` 为规划目录，将随开发逐步建立；`md/` 已存在。

## 快速开始

当前版本尚不可直接运行完整功能，但可以先把开发环境跑起来：

```bash
# 1. 克隆仓库
git clone https://github.com/hyne-lzh/Windows_PE_Inspector.git
cd Windows_PE_Inspector

# 2. 创建虚拟环境
python -m venv .venv

# 3. 激活虚拟环境
.venv\Scripts\activate.bat          # CMD
.\.venv\Scripts\Activate.ps1        # PowerShell

# 4. 安装依赖
pip install -r requirements.txt
```

## 编译为 exe

本项目使用 **Nuitka** 编译（模式固定为 `--standalone`，输出文件夹，便于查错与分发）。

**环境要求**：Python **3.12.x**（不要用 3.13+，MinGW64 后端不支持）、约 1GB 磁盘空间（首次编译需下载约 200MB 的 C 编译器）。

```bash
# 1. 安装编译工具（在已激活的虚拟环境中）
pip install nuitka

# 2. 执行编译（CMD 写法，^ 为续行符）
python -m nuitka ^
  --mingw64 ^
  --assume-yes-for-downloads ^
  --standalone ^
  --enable-plugin=tk-inter ^
  --windows-console-mode=disable ^
  --lto=yes ^
  --python-flag=no_asserts ^
  --python-flag=no_docstrings ^
  --python-flag=no_site ^
  --python-flag=no_warnings ^
  --noinclude-setuptools-mode=nofollow ^
  --output-filename=PEInspector.exe ^
  main.py
```

> PowerShell 的续行符是反引号 `` ` ``，git bash 是 `\`；也可写成**一行**，完全等价。

**产物**：`main.dist/` 文件夹，内含 `PEInspector.exe` 与全部依赖。把整个文件夹拷给别人即可运行。

**几个必须知道的点**（详细说明见 [`md/nuitka_install.md`](md/nuitka_install.md)）：

| 要点 | 说明 |
|------|------|
| `--enable-plugin=tk-inter` **不可省** | Nuitka 不会自动启用该插件，漏掉会导致 exe 启动时缺 tcl/tk 运行时 |
| customtkinter 的 assets | 主题/字体文件由 Nuitka 内置配置自动包含，**无需额外参数** |
| `--assume-yes-for-downloads` | 基本必需：Nuitka 会忽略本机已有的非官方编译器，坚持下载自己的 |
| `--python-flag=no_site` | 要求代码统一用 `sys.exit()`，**不能写 `exit()`** |
| 不使用 `--onefile` | 本项目固定 standalone 模式（启动快、报错可见、便于排查） |

## 开发路线图

| 阶段 | 内容 | 产出 | 状态 |
|------|------|------|------|
| 阶段一 | 环境与仓库初始化 | 虚拟环境、依赖清单、忽略规则 | 已完成 |
| 阶段二 | 界面框架搭建 | 可启动的主窗口与分区布局 | 规划中 |
| 阶段三 | 基础信息展示 | 头信息、节区表、导入表可视化 | 规划中 |
| 阶段四 | 依赖分析 | 缺失 DLL 检测与依赖树 | 规划中 |
| 阶段五 | 特色功能 | 加壳检测、打包器识别、高危 API 标记 | 规划中 |
| 阶段六 | 报告与发布 | 报告导出、Nuitka 编译为 exe | 规划中 |

## 更新日志

### 2026-09-15

- 界面库由 `tkinter` 改为 **customtkinter**（基于 tkinter 的现代化界面库）
- 编译方案确定为 **Nuitka**（原生编译，体积更小、启动更快），模式固定 `--standalone`
- 新增 [`md/nuitka_install.md`](md/nuitka_install.md) 编译指南（含参数逐条说明与 `pkg_resources` 安全性核查）
- 核实编译参数：全部参数经 Nuitka 4.2.1 本地校验

### 2026-09-14

- 搭建工程环境：虚拟环境（Python 3.12.8）、`requirements.txt`、`.gitignore`
- 补充项目说明文档，明确开发状态与功能规划

## 许可

本项目采用 MIT 许可证。

## 作者

**hyne-lzh** · [GitHub](https://github.com/hyne-lzh)

---

**免责声明**：本工具仅用于合法的软件分析与学习研究，不运行、不修改被分析的样本文件。请勿用于任何未授权的用途。
