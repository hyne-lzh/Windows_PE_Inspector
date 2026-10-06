# Windows PE Inspector

![status](https://img.shields.io/badge/status-in%20progress-orange)
![python](https://img.shields.io/badge/python-3.12-blue)
![deps](https://img.shields.io/badge/dependencies-pefile%20%7C%20customtkinter-lightgrey)
![license](https://img.shields.io/badge/license-MIT-green)

> 一个用 Python 写的 Windows PE 文件静态分析工具：把 exe / dll 丢进来，看清它依赖了什么 DLL、是不是被加壳打包、有没有可疑行为——**全程不运行样本**，纯静态解析。

## 项目状态

**状态：图形界面可用（V0.3.0），持续打磨中**

| 模块 | 状态 | 说明 |
|------|------|------|
| 工程环境 | 已完成 | `.venv`（Python 3.12.8）、`requirements.txt`、`.gitignore` |
| 编译链路 | 已完成 | Nuitka 4.2.1 全自动编译脚本（`builds.py`） |
| 解析核心 | 已完成 | `achieve/pe_parser.py`：基本/节区/导入/导出/高危 API 统一解析 |
| 图形界面 | 已完成 | customtkinter 六页（基本信息/节区/导入/导出/高危 API/字符串） |
| 信息面板 | 已完成 | 节区表含中文权限含义列、导入/导出层级树、高危 API 与字符串表格 |
| 高危 API 检测 | 已完成 | 词典外置为 `assets/high_risk_apis.json`（**608 条 / 22 分类**，含内核与驱动层），**已融入导入表按等级着色**：高危红、中危橙、低危黄、安全绿 |
| 字符串提取 | 已完成 | `strings.exe`（Sysinternals）+ pefile 双重来源，失败自动回退；按 **10 类**分组树状展示（URL / IP / 注册表 / 路径 / PDB / XML / 节区名 / DLL 名称 / API 名称 / 其他），URL 检测**容忍 CRL/OCSP 截断**的行首噪音（s/V/a/3/X 等），长内容支持横向滚动 |
| 报告导出 | 已完成 | HTML（单文件自包含）与 Excel（多工作表）双格式 |
| 翻译系统 | 已完成 | 通用翻译表外置（`assets/translations.json`）+ `translate/translate_pair` 通用入口；架构 / 子系统 / 节区权限走同一套翻译，**新增分类只需加 JSON 条目** |
| 加壳检测 | 已完成 | 节区熵值超 7.2 自动标红 + 终端提示 |
| 采样熵 | 已完成 | 节区 > 50 MB 自动改用 4 MB 采样，实测 13x 加速且熵值与全量一致 |
| 打包发布 | 规划中 | Nuitka 编译为免安装 exe（脚本就绪，待发布 Release） |
| DLL 依赖检测 | 规划中 | 检查系统是否存在、位数是否匹配、递归展开依赖树 |
| 打包器识别 | 规划中 | PyInstaller / Nuitka / UPX / VMProtect |
| 数字签名校验 | 规划中 | 判断是否为官方原版 |
| 资源提取 | 规划中 | 图标导出 PNG、版本信息与公司名读取 |
| 批量扫描 | 规划中 | 整个目录一次分析，风险分级汇总 |
| 界面增强 | 已完成 | 文件拖拽（tkinterdnd2）、**浏览即解析**、右键菜单复制/复制全部、表格实时搜索、长内容横向滚动 |

> 进度会在本文件持续更新，每个阶段完成后同步状态。

## 这个工具要解决什么问题

1. **这个程序依赖了什么？** —— 想知道一个 exe 需要哪些 DLL、哪些运行库。
2. **为什么在别人电脑上打不开？** —— 排查缺失的运行库、32/64 位冲突等问题。
3. **这个文件是不是被加壳了？** —— 通过节区熵值判断是否被压缩或加密（含 VMP、UPX、PyInstaller 特征）。
4. **它是用什么打包的？** —— 识别 PyInstaller、Nuitka、UPX 等常见打包器。
5. **这个文件可疑吗？** —— **基于 608 条高危 API 词表静态匹配**，覆盖用户态（进程注入 / 反调试 / 键盘记录 / 网络下载）与**内核驱动层**（内核钩子 / 驱动加载 / 网络过滤 / BYOVD 相关）共 22 类，**不运行样本**即可初筛。

## 功能规划

### 已完成

- [x] 创建项目虚拟环境与依赖清单
- [x] 配置 Git 忽略规则（虚拟环境、打包产物、IDE 配置等）
- [x] 确定技术选型与 Nuitka 编译参数
- [x] PE 文件解析核心（`achieve/pe_parser.py`，CLI 与 GUI 共用）
- [x] 基础信息面板：架构位数、编译时间戳、入口点、校验和
- [x] 节区表格：名称/大小/权限/中文含义/熵值/标记
- [x] 加壳检测：熵值超阈值时红色高亮 + 终端提示
- [x] 导入 / 导出表：DLL 与函数层级树形展示
- [x] 高危 API 标记：608 条敏感 API 词表（外置 JSON，可自行扩充），按严重 / 中等 / 低分级着色，并融入导入表
- [x] 字符串提取：`strings.exe` + pefile 双重来源，按 10 类分组树状展示（URL / IP / 注册表 / 路径 / PDB / XML / 节区名 / DLL 名称 / API 名称 / 其他），长内容可横向滚动
- [x] 字符串分类增强：URL 检测容忍 1 字节行首噪音（`s` / `V` / `a` / `3` / `X` 等），吸收 CRL/OCSP 截断
- [x] 报告导出：HTML（单文件自包含）与 Excel（多工作表）双格式
- [x] 采样熵：超大节区（>50 MB）改用 4 MB 采样，实测 13x 加速
- [x] 翻译系统：架构 / 子系统英文后接中文；通用翻译表外置为 `assets/translations.json`，新增分类只需加 JSON 条目（`translate(cat, key)` / `translate_pair(cat, key)` 统一入口）
- [x] 界面增强：文件拖拽（tkinterdnd2）、**浏览即解析**（选中即跑）、右键菜单复制 / 复制全部、表格实时搜索、长内容横向滚动

### 规划中

- [ ] DLL 依赖检测：检查系统是否存在、位数是否匹配、递归展开依赖树
- [ ] 打包器识别：PyInstaller / Nuitka / UPX / VMProtect（本项目自身也用 Nuitka 编译）
- [ ] 数字签名校验：判断是否为官方原版
- [ ] 资源提取：图标导出 PNG、版本信息与公司名读取
- [ ] 批量扫描：整个目录一次分析，风险分级汇总
- [ ] GitHub Release 发布 Nuitka 编译后的 exe

## 技术栈

| 层次 | 选型 | 说明 |
|------|------|------|
| 语言 | Python 3.12 | 使用 Python 3.12.8 构建环境（**不要用 3.13+**，见编译说明） |
| PE 解析 | [pefile](https://github.com/erocarrera/pefile) | 成熟的 PE 文件解析库 |
| 图形界面 | [customtkinter](https://customtkinter.tomschimansky.com/) | 基于 tkinter 的现代化界面库，外观更现代 |
| 报告导出 | openpyxl | 导出 Excel 汇总表（待引入） |
| 编译 | [Nuitka](https://nuitka.net/) | 编译为原生机器码，体积更小、启动更快 |

**设计原则：依赖保持精简、精确锁版本，便于分发与编译。**

## 安全设计（本工具自身的防护）

本工具会被用来分析**恶意样本**，所以它自身必须健壮。已落实的防护：

| 防护 | 说明 |
|------|------|
| **绝不运行样本** | 全程只读 / mmap 静态解析；无 `LoadLibrary`、`ShellExecute`、`exec`，样本从未被执行 |
| **句柄不泄漏** | `parse_pe()` 用统一 `try/finally`，无论在哪一步失败都保证 `pe.close()` 执行 |
| **异常不裸抛** | 所有异常归一化为 `PeParseError`（含中文文案与退出码）；畸形 PE 只优雅报错，CLI 不会 traceback |
| **Excel 公式注入防护** | 样本里的 DLL / 函数名可能以 `=` 开头（如 `=HYPERLINK(...)`），写入 xlsx 前统一加前导单引号中和 |
| **HTML 转义** | 报告中的样本字符串全部 `html.escape(quote=True)`，并限制字符串区块条数 |
| **输入上限** | 超过 2 GB 的文件直接拒绝解析，防止恶意大文件耗尽内存 |
| **外部工具安全** | `strings.exe` 用 argv 列表调用（非 shell）且带超时；失败 / 缺失时自动回退 pefile，绝不抛异常 |

## 目录结构

```
Windows_PE_Inspector/
├── main.py                # GUI 入口（无命令行，双击即开界面）
├── cmd_main.py            # CLI 入口（python cmd_main.py <PE 文件> [选项]）
├── builds.py              # 全自动编译脚本（环境预检 + 网络诊断 + 测速选后端）
├── achieve/               # GUI 与 CLI 共用的实现逻辑（不依赖任何 GUI 库）
│   ├── __init__.py
│   ├── pe_parser.py       # 解析核心 + 数据类 + 通用翻译表 + 高危 API 词典
│   ├── strings_extractor.py  # strings.exe + pefile 双重来源 + 10 类分类
│   └── report_exporter.py    # HTML / Excel 报告导出（含公式注入/转义防护）
├── assets/                # 外置数据词典（用户可自行扩充，无需改代码）
│   ├── high_risk_apis.json   # 608 条高危 API，按 22 分类 + 严重度分级
│   └── translations.json     # 通用翻译表（SECTION_FLAGS / MACHINE / SUBSYSTEM / DLL）
├── ui/                    # GUI 专用
│   ├── __init__.py
│   └── gui.py             # customtkinter 主窗口（六页 + 后台线程 + 状态栏）
├── cli/                   # CLI 专用
│   ├── __init__.py
│   └── cli.py             # 命令行打印 + argparse
├── strings.exe            # Sysinternals Strings v2.54（外部字符串提取工具）
├── md/
│   └── nuitka_install.md  # Nuitka 编译指南
├── requirements.txt       # 依赖清单（pefile + customtkinter + openpyxl，精确锁版本）
├── LICENSE.txt            # MIT 许可证全文
├── .gitignore
└── README.md
```

> 设计原则：解析逻辑**一份真相源**，`parse_pe()` 同时被 GUI 和 CLI 调用；GUI/CLI 专用代码物理隔离。

## 快速开始

```bash
# 1. 克隆仓库
git clone https://github.com/hyne-lzh/Windows_PE_Inspector.git
cd Windows_PE_Inspector

# 2. 创建并激活虚拟环境
python -m venv .venv
.venv\Scripts\activate.bat          # CMD
.\.venv\Scripts\Activate.ps1        # PowerShell

# 3. 安装依赖
pip install -r requirements.txt

# 4. 运行（任选其一）
python main.py                        # 图形界面（双击 exe 等价）
python cmd_main.py <PE 文件路径>      # 命令行（例：python cmd_main.py notepad.exe --all）
python cmd_main.py notepad.exe --risks  # 仅查看高危 API
```

> 双击 `main.py` 或编译后的 `PEInspector.exe` 直接打开 GUI；命令行版本与 GUI 共用同一份解析逻辑。

## 界面操作小贴士

- **拖放**：把 exe / dll / sys 直接拖到窗口任意位置即可，自动填入路径并开始分析。拖入多个文件时只取第一个；非 PE 文件照常弹出解析失败提示。
- **浏览即解析**：点「浏览…」按钮在文件对话框里确认后**自动开始分析**（与拖入行为一致）；「开始分析」按钮保留作为手动重跑入口（重试失败 / 重跑同一文件时分析 `_worker.is_alive()` 自动去重）。
- **搜索**：节区 / 导入表 / 导出表 / 高危 API / 字符串五个分页顶部都有搜索框，输入即时过滤（不区分大小写，匹配任意一列）。导入表里搜 DLL 名会整组保留，搜函数名则只列出命中的函数并自动展开所属 DLL。清空搜索框即还原全部行，**行的风险着色不受过滤影响**。
- **复制**：任意表格里右键 →「复制」/「复制全部」。列表表格按制表符分列，**可直接粘贴进 Excel**。树形分页（导入表 / 字符串）选中 **DLL 或分组父节点**「复制」时，得到该组下**全部子项**（不含标题行，也不含"…其余 N 条"提示行），粘出来是干净数据列；想连标题一起复制就用「复制全部」。状态栏提示实际复制行数。

## 编译为 exe

本项目使用 **Nuitka** 编译（模式固定为 `--standalone`，输出文件夹，便于查错与分发）。

完整指南（含 5 步全自动流程 / 手动编译命令 / 网络限速兜底 / 参数逐条说明 / 验证清单）见 [`md/nuitka_install.md`](md/nuitka_install.md)。

最常用两条命令：

```bash
pip install nuitka             # 首次：安装编译工具
python builds.py               # 全自动编译（自动测速、择优编译器后端）
```

> 终端用户**不需要编译**——把 `main.dist/` 压成 zip 作为 Release 附件即可。

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

### 2026-10-06

- **重构翻译为通用架构**：合并节区权限 / 架构 / 子系统三块独立字典为单一 `_BUILTIN_TRANSLATIONS`，新增通用入口 `translate(category, key)` / `translate_pair(category, key)`；新增外置 `assets/translations.json`（SECTION_FLAGS / MACHINE / SUBSYSTEM / DLL 占位），用户可自行扩充，无需改代码
- **架构 / 子系统翻译**：基本信息面板新增英文（中文）一行展示，架构单独成行
- **浏览即解析**：`_browse()` 选完文件后自动触发分析，与拖入行为一致；「开始分析」按钮保留作为手动重跑入口
- **CRL/OCSP 截断 URL 修复**：字符串分类器 URL 检测由「`^https?://` 严格锚定」改为三层（剥噪音 + 跳 1 字节 + 全文检索），吸收 CRL/OCSP 字符串常见的 `s` / `V` / `a` / `3` / `X` 等 1 字节行首噪音
- **README 与 nuitka_install.md 去重合并**：把 README 的「## 编译为 exe」整段（87 行重复说明）全部合并进 [`md/nuitka_install.md`](md/nuitka_install.md)，README 仅保留速查两条命令 + 指针，避免两处维护
- **新增 `LICENSE.txt`**：MIT 许可证全文落地（此前只在 README 里口头声明「采用 MIT」，仓库内无正式许可文件）；README 许可章节与目录结构同步指向该文件
- **Nuitka 实编验证跑通**：`main.dist/PEInspector.exe`（20.9 MB，总目录 46 MB / 1062 文件），启动 6 秒进程存活无闪退、无异常日志；外置数据全部进包（`assets/`、`strings.exe`）

### 2026-09-26

- **修复所有分页表格空白的问题**：根因是 `Treeview.grid(in_=holder)` 跨父布局；改为纯 `pack` 顺序（滚动条先放，再 `tree.pack(side="left", fill="both", expand=True)`）
- **高危 API 词典扩充至 608 条 / 22 分类**：新增内核与驱动层（内核钩子 / 驱动加载 / 网络过滤 / BYOVD 相关），按严重度着色融入导入表
- **字符串分类增强**：按 10 类分组树状展示（新增 XML / 节区名 / DLL 名 / API 名 分类，减少其他桶 29% 噪音）；长内容支持横向滚动

### 2026-09-20

- **新增字符串提取**：`strings.exe`（Sysinternals）+ pefile 双重来源，失败自动回退，按 10 类分组展示
- **新增报告导出**：HTML（单文件自包含，CSS 内联）与 Excel（多工作表）双格式，自动按保存对话框扩展名分派
- **三项安全问题修复**：Excel 写入前对 `=` / `/` / `@` 等开头字符加单引号中和（防公式注入）、HTML 字符串全 `html.escape(quote=True)`、文件大小 2 GB 上限防恶意大文件耗内存
- **节区权限中文翻译**：表新增「含义」列（贪婪匹配 UDATA 5 / IDATA 5 / CODE 4 / X/R/W 1）
- **采样熵**：>50 MB 节区改用 4 MB 采样，实测 13x 加速

### 2026-09-17

- **目录结构改为 CLI/GUI 双入口**：解析核心（`achieve/pe_parser.py`）作为单一真相源同时被 GUI（`main.py`）和 CLI（`cmd_main.py`）调用；GUI 专用放 `ui/gui.py`，CLI 专用放 `cli/cli.py`
- **新增 customtkinter 图形界面**：六页（基本信息 / 节区 / 导入表 / 导出表 / 高危 API / 字符串）+ 后台线程 + 状态栏

### 2026-09-16

- 新增 **`builds.py`** 一键编译脚本：环境预检（拦住 Python 3.13+）、参数固化、耗时报告
- `builds.py` 升级为**全自动**：编译器缓存检查 → 网络与加速器诊断 → 实测测速 → 自动择优后端 → 编译
- `builds.py` 新增**加速器识别**：读 hosts / 代理环境变量 / 系统代理与 `github.com` 解析 IP，避免被加速器干扰测速判断
- `builds.py` 新增**代理绕行复测**：挂了代理却测速失败时自动直连再测一次，区分"网络不行"与"代理有问题"
- 编译指南新增「**两种编译方式**」：脚本编译 / 手动编译
- 编译指南新增「**网络受限：两条路线**」：先实测下载速度（不用 ping）→ 挂 GitHub520 hosts → 仍不达标换 `--zig` 后端
- 补充「**兜底：完全离线**」方案：手动预置编译器包到 Nuitka 缓存目录，可零下载编译
- 实测数据入档：MinGW64 安装包 255 MB、`ziglang` wheel 94.1 MB、GitHub 直连测速 0.57 MB/s

### 2026-09-15

- 界面库由 `tkinter` 改为 **customtkinter**（基于 tkinter 的现代化界面库）
- 编译方案确定为 **Nuitka**（原生编译，体积更小、启动更快），模式固定 `--standalone`
- 新增 [`md/nuitka_install.md`](md/nuitka_install.md) 编译指南（含参数逐条说明与 `pkg_resources` 安全性核查）
- 核实编译参数：全部参数经 Nuitka 4.2.1 本地校验

### 2026-09-14

- 搭建工程环境：虚拟环境（Python 3.12.8）、`requirements.txt`、`.gitignore`
- 补充项目说明文档，明确开发状态与功能规划

## 许可

本项目采用 **MIT 许可证**，全文见 [`LICENSE.txt`](LICENSE.txt)。

Copyright (c) 2026 hyne-lzh

## 作者

**hyne-lzh** · [GitHub](https://github.com/hyne-lzh)

---

**免责声明**：本工具仅用于合法的软件分析与学习研究，不运行、不修改被分析的样本文件。请勿用于任何未授权的用途。
