# Nuitka 编译指南

本文档说明如何把 Windows PE Inspector 编译为可分发的 exe。

> 参数已用 **Nuitka 4.2.1**（本项目 `.venv` 内实测）与 Nuitka 源码逐个核对，非网络抄录。
> 编译模式统一使用 **`--standalone`**（输出文件夹），**本项目不使用 `--onefile`**。

---

## 环境要求

| 项目 | 要求 |
|------|------|
| Python | **3.12.x**（本项目 3.12.8；**不要用 3.13+**，见下方说明） |
| Nuitka | 4.2.1（实测版本） |
| C 编译器 | MinGW64（由 Nuitka 自动下载，约 200MB） |
| 磁盘空间 | 建议预留 1GB 以上（编译器 + 中间产物） |

### 为什么不能用 Python 3.13+

MinGW64 后端**官方不支持 Python 3.13 及以上**，除非加实验性参数 `--experimental=force-mingw64`（不推荐）。
本项目锁定 Python 3.12.8，不受影响。

### 为什么 `--assume-yes-for-downloads` 是必需的

Nuitka **会忽略"非官方下载"的编译器**。实测本机虽已有 `C:\GCC\mingw64\bin\gcc.exe`（gcc 15.2.0），Nuitka 仍提示：

```
Non downloaded winlibs-gcc 'C:\GCC\mingw64\bin\gcc.exe' is being ignored,
Nuitka is very dependent on the precise one.
```

它坚持使用自己下载的版本，因此首次编译必须允许自动下载。

---

## 完整编译命令

```bash
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

> 上面是 **CMD** 写法（`^` 为续行符）。PowerShell 用反引号 `` ` ``，git bash 用 `\`。
> 嫌续行麻烦可写成**一行**，完全等价。

### 编译前的准备

```bash
python -m venv .venv
.venv\Scripts\activate.bat
pip install -r requirements.txt
pip install nuitka
```

---

## 参数逐条说明

### 编译与分发

| 参数 | 作用 |
|------|------|
| `--mingw64` | 使用 MinGW64 编译器（Nuitka 自动下载官方版本） |
| `--assume-yes-for-downloads` | 自动确认下载编译器/依赖，免交互 |
| `--standalone` | 生成**独立文件夹**（含解释器与全部依赖），拷到其他机器可直接运行 |
| `--output-filename=PEInspector.exe` | 指定产物 exe 名称，替代默认的 `main.exe` |

### 界面相关

| 参数 | 作用 |
|------|------|
| `--enable-plugin=tk-inter` | **启用 tkinter 插件**，打包 tcl/tk 运行时文件（**本项目必需**） |
| `--windows-console-mode=disable` | 不创建、不使用控制台窗口（GUI 必备，等价 pythonw 行为） |

### 优化

| 参数 | 作用 |
|------|------|
| `--lto=yes` | 链接时优化：跨文件内联 + 死代码消除，通常再缩 10%~15%（编译变慢）。取值 `yes`/`no`/`auto` |

### Python 运行时标志（`--python-flag`）

与标准 Python 命令行的 `-O`、`-S` 等一一对应，用于**瘦身 + 去特征**：

| 参数 | 等价 | 作用 | 副作用 |
|------|------|------|--------|
| `--python-flag=no_asserts` | `-O` | 去掉 `assert` 断言语句 | **断言不再执行**，别用 assert 做参数校验 |
| `--python-flag=no_docstrings` | — | 剥离 docstring | exe 二进制中不再出现说明类明文字符串 |
| `--python-flag=no_site` | `-S` | 跳过 `site.py` | **`exit()` / `quit()` 等内建函数消失**，必须改用 `sys.exit()` |
| `--python-flag=no_warnings` | — | 关闭运行时警告输出 | 减少控制台 Python 特征 |

> ⚠️ **`no_site` 影响的是代码写法，不是打包结果**：本项目所有退出路径必须写 `sys.exit(0)`，不能写 `exit()`。

### 依赖裁剪

| 参数 | 作用 |
|------|------|
| `--noinclude-setuptools-mode=nofollow` | 遇到 `setuptools` / `pkg_resources` 的 import 时不跟随（该包及依赖体积很大） |

取值三选一：`error`（报错中断）、`warning`（警告但继续）、`nofollow`（不跟随，推荐）。

---

## 核查项：`--noinclude-setuptools-mode=nofollow` 是否安全

**结论：对本项目安全，可以放心添加。** 核查过程如下。

### 核查方法

直接检查项目实际安装的每一个运行期依赖，看是否 import `pkg_resources` 或 `setuptools`：

```bash
grep -rn "pkg_resources\|import setuptools\|from setuptools" \
  .venv/Lib/site-packages/customtkinter/ \
  .venv/Lib/site-packages/darkdetect/ \
  .venv/Lib/site-packages/packaging/ \
  .venv/Lib/site-packages/pefile.py
```

### 核查结果

| 依赖 | 是否依赖 pkg_resources / setuptools | 说明 |
|------|--------------------------------------|------|
| `pefile` | **否** | 顶层 import 全部是标准库（`codecs`、`collections`、`struct`、`hashlib`、`typing` 等） |
| `customtkinter` | **否** | 无任何 setuptools 相关引用 |
| `darkdetect` | **否** | 极小的系统主题探测库 |
| `packaging` | **否** | 它本身就是 `pkg_resources` 的**现代替代品**，只用 `packaging.version` / `packaging.specifiers` |

**grep 无任何命中**，即全部 4 个依赖都不使用 `pkg_resources`。因此排除 setuptools 不会造成运行时异常。

### 何时需要去掉这个参数

`--noinclude-setuptools-mode=nofollow` 的风险只在于：某些库会在**运行时**用 `pkg_resources.get_distribution()` 读取自身版本号。
若日后引入此类库，需去掉该参数，或改为更温和的：

```bash
--noinclude-setuptools-mode=warning
```

（`warning` = 遇到 setuptools 就告警但**仍按需跟随**，安全但不省体积。）

---

## 界面库：customtkinter 的打包注意点

本项目界面使用 **customtkinter**（基于 tkinter 的现代化封装）。

### 1. tcl/tk 运行时仍然需要

customtkinter 底层就是 tkinter，所以 **`--enable-plugin=tk-inter` 照样必需**。

> 依据（已核对 Nuitka 4.2.1 源码）：
> - `nuitka/plugins/standard/TkinterPlugin.py` 中的实际插件类 `NuitkaPluginTkinter` **未定义 `isAlwaysEnabled()`**，而该方法默认返回 `False`（见 `PluginBase.py`）→ **插件不会自动启用**。
> - 该文件另有一个探测器类 `NuitkaPluginDetectorTkinter`，它的唯一作用是在主模块出现 `tkinter` 字样却**未启用插件**时，调用 `warnUnusedPlugin("Tkinter needs TCL included.")` —— **只告警，不自动补上**。
> - 由于 `import customtkinter` 这行本身就含 `tkinter` 子串，探测器一定会触发并告警，但**告警不等于能跑**。

**若不加此参数**：exe 能编译出来，但启动时会因缺 tcl/tk 运行时文件而失败。

### 2. customtkinter 的 assets 会被自动包含

customtkinter 在**运行时**用 `open()` 读取主题与字体文件，例如 `theme_manager.py`：

```python
with open(os.path.join(customtkinter_path, "assets", "themes", f"{theme_name_or_path}.json"), "r") as f:
```

这些文件必须进包，否则运行时报 `FileNotFoundError`：

| 路径 | 内容 |
|------|------|
| `assets/themes/*.json` | `blue`、`dark-blue`、`gold`、`green` 四套主题 |
| `assets/fonts/` | `CustomTkinter_shapes_font.otf`、`Roboto-Medium.ttf`、`Roboto-Regular.ttf` |
| `assets/icons/` | `CustomTkinter_icon_Windows.ico` |

**好消息**：Nuitka 4.2.1 内置了 customtkinter 的包配置，**无需手动加参数**。依据 `nuitka/plugins/standard/standard.nuitka-package.config.yml`：

```yaml
- module-name: 'customtkinter'
  data-files:
    - dirs:
        - 'assets'
```

**兜底方案**：若换用其他 Nuitka 版本、或运行时出现主题/字体加载失败，追加：

```bash
--include-package-data=customtkinter
```

customtkinter **没有专用插件**（`--plugin-list` 中不存在 customtkinter 条目），完全依靠上述 YAML 配置处理。

---

## 编译产物与验证

编译完成后产物结构：

```
main.dist/                    # 独立目录（把整个文件夹拷给别人即可运行）
├── PEInspector.exe           # 主程序（名字由 --output-filename 决定）
├── python312.dll             # Python 运行时
├── tcl/ tk/ ...              # tcl/tk 运行时（由 tk-inter 插件带入）
└── customtkinter/assets/     # 主题、字体、图标
```

### 验证清单

1. 双击 `main.dist\PEInspector.exe`，确认窗口正常出现、主题正常加载（无 `FileNotFoundError`）。
2. 在**干净机器或虚拟机**上测试（本机因已装 Python 可能"假正常"）。
3. 测试边界场景：非 PE 文件、损坏文件、超大文件、空文件。
4. 确认用 `sys.exit()` 而非 `exit()`（`no_site` 会导致后者报 `NameError`）。

---

## 常见问题排查

| 现象 | 原因 | 解决 |
|------|------|------|
| 双击 exe 闪退 | 控制台已关闭，看不到报错 | 临时改 `--windows-console-mode=attach`，从命令行运行看错误 |
| 启动报缺 tcl/tk | 未启用 tk-inter 插件 | 加上 `--enable-plugin=tk-inter` |
| 主题/字体加载失败 | assets 未打进包 | 加 `--include-package-data=customtkinter` |
| `exit()` 报 NameError | 用了 `--python-flag=no_site` | 统一改用 `sys.exit()` |
| 报 `No module named 'xxx'` | 模块被排除或未追踪到 | 用 `--include-module=xxx` 加回，**分批补** |
| 编译太慢 | 默认单线程 | 加 `--jobs=N`（N = CPU 核心数） |
| 图标没生效 | 路径含空格或格式问题 | 用绝对路径；`.ico` 最稳 |
| 版本号写入失败 | 含字母或字符 | 版本号**只能是数字**，如 `1.0.0.0` |
| 首次编译卡住 | 正在下载约 200MB 编译器 | 耐心等待，或配好编译器后再编译 |

### 排查利器

| 手段 | 用途 |
|------|------|
| `--report=compilation-report.xml` | 生成 XML 报告，逐模块列出是否包含、占多大 —— **定位"谁在吃体积"最有效** |
| `--show-scons` | 打印编译阶段每个 `.obj` / `.lib` 路径 |
| `--windows-console-mode=attach` | 让 GUI 程序在命令行下显示报错 |
| `python -m nuitka --help` | 参数以本地版本为准（官方推荐做法） |
| `python -m nuitka --plugin-list` | 查看当前版本可用插件 |

---

## 体积优化（可选）

| 手段 | 效果 | 代价 |
|------|------|------|
| 精确排除模块 `--nofollow-import-to=xxx` | **最大** | 需测试，可能漏补模块 |
| `--lto=yes` | 再缩 10%~15% | 编译变慢（已含在命令中） |
| UPX（`--enable-plugin=upx`） | 再压一截 | **杀软误报 + 启动变慢** |

> ⚠️ **不建议默认启用 UPX**：一个 PE 安全分析工具自身被报毒，场面太尴尬。真要压体积，先发不加壳的版本确认无误报再启用。

> ⚠️ **不要用 `--nofollow-imports`** 粗放裁剪——极易漏掉隐式依赖，运行时一串 `ModuleNotFoundError`；官方文档也明确说明该参数**不可用于 standalone 模式**。要排除就精确排除。

---

## 参考资料

- [Nuitka 官方文档 - Use Cases](https://nuitka.net/user-documentation/use-cases.html)
- [Nuitka 官方文档 - User Manual](https://nuitka.net/user-documentation/user-manual.html)
- [customtkinter 官方文档](https://customtkinter.tomschimansky.com/)

> 参数核对方式：`python -m nuitka --help` / `--version`（本地 4.2.1 实测）、Nuitka 源码
> `nuitka/plugins/standard/TkinterPlugin.py`、`nuitka/plugins/Plugins.py`、`nuitka/plugins/PluginBase.py`
> 与 `standard.nuitka-package.config.yml`。
