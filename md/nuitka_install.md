# Nuitka 编译指南

本文档说明如何把 Windows PE Inspector 编译为可分发的 exe。

> 参数已用 **Nuitka 4.2.1**（本项目 `.venv` 内实测）与 Nuitka 源码逐个核对，非网络抄录。
> 编译模式统一使用 **`--standalone`**（输出文件夹），**本项目不使用 `--onefile`**。

---

## 速查表

| 你想做什么 | 命令 |
|-----------|------|
| **全自动编译**（推荐，自动测速择后端） | `python builds.py` |
| 强制指定后端 | `python builds.py --backend mingw64` / `--backend zig` |
| 调整自动切换阈值（默认 1.0 MB/s） | `python builds.py --min-speed 1.5` |
| **网络诊断 + 测下载速度** | `python builds.py --test-net` |
| 检查环境、编译器缓存与网络状态 | `python builds.py --check-env` |
| 只看编译命令、不真编译 | `python builds.py --dry-run` |
| 清理产物 | `python builds.py --clean` |
| 手动编译（不用脚本） | 见「方式二：手动编译」 |
| 网络慢 / 下不动编译器 | 见「网络受限：两条路线」 |

---

## 环境要求

| 项目 | 要求 |
|------|------|
| Python | **3.12.x**（本项目 3.12.8；**不要用 3.13+**，见下方说明） |
| Nuitka | 4.2.1（实测版本） |
| C 编译器 | **MinGW64**（默认，Nuitka 自动下载，实测 **255 MB**）<br>或 **Zig**（备选，走 PyPI，实测 **94 MB**，见「路线二」） |
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

## 两种编译方式

### 方式一：使用 `builds.py`（推荐，全自动）

仓库根目录带有编译脚本 `builds.py`，只依赖标准库。**它可以不带任何参数直接跑**——会先摸清你的网络，再自己决定用哪个编译器后端。

```bash
# 1. 准备环境（首次）
python -m venv .venv
.venv\Scripts\activate.bat          # CMD
.\.venv\Scripts\Activate.ps1        # PowerShell
pip install -r requirements.txt
pip install nuitka

# 2. 编译（全自动，不需要参数）
python builds.py

# 3. 只想先看看会执行什么
python builds.py --dry-run
```

**5 步全自动流程**：

| 步骤 | 说明 |
|------|------|
| 1/5 环境检查 | 校验 Python 版本（拦住 3.13+）、确认 Nuitka 已安装、确认 `main.py` 存在 |
| 2/5 编译器缓存 | 检查 MinGW64（winlibs zip 或解压后的 `gcc.exe`）与 Zig 是否已就位 |
| 3/5 网络与代理诊断 | 读 hosts、代理环境变量、系统代理，并解析 `github.com` 的真实 IP |
| 4/5 **自动选择后端** | 见下方决策规则 |
| 5/5 编译 | 执行 Nuitka，报告耗时、产物路径与目录体积 |

**第 4 步的决策规则**（`--backend auto`，默认）：

```
① 本地已缓存 MinGW64 ──────────→ 用 MinGW64（零下载，连测速都跳过）
② 否则已缓存 Zig ──────────────→ 用 Zig（零下载）
③ 两个都没缓存 → 先测 GitHub 速度
      · ≥ --min-speed（默认 1.0 MB/s）→ MinGW64
      · 低于阈值或测速失败 ─────────→ 再测 PyPI，确认可行后用 Zig
```

也就是说：**编译器已经在本地时不去碰网络；真的需要下载时才测速择优。** 想固定后端就显式指定：

```bash
python builds.py --backend mingw64   # 强制 MinGW64
python builds.py --backend zig       # 强制 Zig
python builds.py --min-speed 1.5     # 提高阈值，更容易切到 Zig
python builds.py --jobs=4            # 指定并行编译进程数
```

`--check-env` 会把环境、缓存、网络三者一次查清：

```bash
python builds.py --check-env
```

---

### 关于加速器：脚本会主动识别并提醒

若本机装了 Steam++ / Watt Toolkit 一类工具，它会做两件事：把 GitHub 域名写进 hosts 指向 `127.0.0.1`，并开启一个本地代理端口。**这会让"测速结果"失去参考价值**——测速通过只说明"加速器此刻在运行"，不代表编译时也能下动。

所以 `builds.py` 在网络诊断阶段会明确报出来：

```
  [!] hosts 中 27 条 GitHub 域名被指向回环地址
  [!] 检测到代理环境变量：HTTP_PROXY=http://127.0.0.1:52013 ...
  [!] github.com 解析到 127.0.0.1（本机回环）—— 已确认由加速器接管
```

看到这段提示时请注意三点：

1. **只有加速器在运行时 GitHub 才连通**；没运行的话是"连接被立即拒绝"，不是慢。
2. **编译全程不要中途开关加速器**，否则 255 MB 的下载会断在半路。
3. 若测速失败但本机确实挂着代理，脚本会**自动绕过代理再测一次**，用来区分"网络不行"还是"加速器本身有问题"。

### 方式二：手动编译

不用脚本，直接执行 Nuitka 命令（参数与 `builds.py` 完全一致）：

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
>
> **换 Zig 后端**：把 `--mingw64` 换成 `--zig`，其余不变。

---

## 网络受限：两条路线

首次编译需要下载 C 编译器（MinGW64 255 MB）。若 GitHub 访问缓慢甚至失败，按下面的顺序处理。

### 第 0 步：先测速（不要用 ping）

**`ping` 的结果在这里基本没有参考价值**，原因有三：

1. ICMP 与 HTTP 下载走的是**不同的服务器和 CDN 节点**，ping 到 A 不代表能从 B 下文件；
2. GitHub 对 ICMP 常常直接丢弃或限速，导致"ping 不通但其实能下"，或"ping 很通但下载龟速"；
3. ping 测的是**单包往返延迟（毫秒）**，而决定下载时长的是**吞吐量（MB/s）**，两者不是一回事。

正确做法：**直接对真正要下载的那个文件发起一次短时 HTTP 下载，实测吞吐。**

```bash
# 推荐：用脚本测（最多取 5 MB / 最多 15 秒）
python builds.py --test-net
```

> **全自动模式下不用手动跑这一步**——`python builds.py` 的第 4 步会在需要下载时自动测速并择优；
> 上面这条命令适合"我想单独看一眼网络到底怎么样"。
> 若本机挂了代理/加速器而测速失败，脚本会自动**绕过代理再测一次**，以区分"网络不行"还是"加速器本身有问题"。

等价的手动命令（curl，Windows 10+ 自带）：

```bash
# Windows：NUL 表示丢弃输出
curl -L -o NUL -w "速度: %{speed_download} 字节/秒  用时: %{time_total} 秒\n" --max-time 20 -r 0-5242879 "<winlibs 安装包 URL>"

# Linux / macOS：丢弃输出用 /dev/null
curl -L -o /dev/null -w "速度: %{speed_download} 字节/秒  用时: %{time_total} 秒\n" --max-time 20 -r 0-5242879 "<winlibs 安装包 URL>"
```

> 完整的 winlibs URL 见 `builds.py` 中的 `WINLIBS_URL` 常量（含版本号，升级 Nuitka 后可能变化）。

**判定标准**：

| 实测速度 | 结论 | 动作 |
|---------|------|------|
| ≥ 2 MB/s | 直连良好 | 直接编译，无需处理 |
| 0.5 ~ 2 MB/s | 能下但慢（255 MB 约 2–8 分钟） | 建议先试「路线一」 |
| < 0.5 MB/s 或失败 | 太慢/不通 | 「路线一」→ 仍不行走「路线二」 |

> 本机实测参考（2026-09-16）：**0.57 MB/s**，完整安装包预计约 7 分钟。

---

### 路线一：挂 GitHub520 hosts（国内外通用）

**适用性**：不限地区——**先测速，达标就不用做**。国内用户通常受益明显；海外用户 GitHub 本来就快，测速通过即可跳过。

**步骤**（编辑 hosts 需要管理员权限）：

```bash
# 1) 先备份（重要）
copy C:\Windows\System32\drivers\etc\hosts C:\Windows\System32\drivers\etc\hosts.bak

# 2) 下载最新 hosts 片段
curl -L -o "%TEMP%\github520_hosts.txt" https://raw.hellogithub.com/hosts

# 3) 用管理员身份打开 hosts，把上一步内容粘贴进去
notepad C:\Windows\System32\drivers\etc\hosts

# 4) 刷新 DNS 缓存
ipconfig /flushdns

# 5) 重新测速，确认是否改善
python builds.py --test-net
```

该文件以 `# GitHub520 Host Start` / `# GitHub520 Host End` 包裹，**更新时整块替换**即可。

**⚠️ 必须注意：不能"追加"，要处理冲突**

如果 hosts 中**已有加速器段落**（Steam++ / Watt Toolkit / 其他 GitHub 加速工具），它们通常把 GitHub 域名指向 `127.0.0.1` 由本地反代接管。此时：

- Windows 解析 hosts 时**取第一条匹配**，把新条目追加在后面**完全不会生效**；
- 而且如果那个加速器**没有在运行**，`127.0.0.1` 会让 GitHub **直接不可达**（连接被立即拒绝，不是慢）。

所以正确做法是：**先把已有的 GitHub 加速段落整段注释掉**（前面加 `#`，想用时再打开），再粘贴 GitHub520 的内容。

**覆盖范围**（按该文件实测内容）：

| 域名 | 是否覆盖 |
|------|---------|
| `github.com` | ✅ |
| `api.github.com` | ✅ |
| `objects.githubusercontent.com`（**大文件实际走这里**） | ✅ |
| `github-production-release-asset-2e65be.s3.amazonaws.com` | ✅ |
| `raw.githubusercontent.com` | ✅ |
| `release-assets.githubusercontent.com` | ❌ 未覆盖（GitHub 较新的资源 CDN） |

**局限性**：hosts 只解决"解析到哪个 IP"，**不解决 CDN 限速**。对 255 MB 的大文件，效果通常是从"连不上"变成"能连"，但速度提升不保证。

---

### 路线二：换 Zig 后端（绕开 GitHub）

**原理**：Nuitka 的 `--zig` 后端不使用 GitHub，而是**通过 pip 把 `ziglang` 装进 Nuitka 自己的私有 pip 空间**：

```
%LOCALAPPDATA%\Nuitka\Nuitka\Cache\downloads\pip\private-<hash>\Lib\site-packages\ziglang\
```

**用法**：

```bash
python builds.py --backend zig
```

或手动编译时把 `--mingw64` 换成 `--zig`（其余参数不变）。`--assume-yes-for-downloads` 需保留，pip 安装由它自动确认。

**为什么能绕过 GitHub**（体积为实测值）：

| 后端 | 下载内容 | 体积 | 下载来源 |
|------|---------|------|---------|
| `--mingw64`（默认） | winlibs MinGW64 安装包 | **255 MB** | GitHub Release |
| `--zig` | `ziglang` wheel | **94 MB** | **PyPI（与 GitHub 无关）** |

既更小，又换了一条链路，因此在国内环境下成功率更高。

**注意事项**：

- **使用 PyPI 官方默认源即可，不要为它额外配置国内镜像**——保持通用，海外用户同样适用；若本机已配镜像也不影响。
- 首次使用会由 pip 自动下载约 94 MB，解压后占用约 **381 MB**（其中 `zig.exe` 本身 169 MB）。
- `--zig` 是相对较新的后端，**首次切换后请完整跑一遍「验证清单」**，确认产物能正常启动、界面正常。

---

### 兜底：完全离线（预置编译器包）

如果目标机器完全无法访问 GitHub 与 PyPI，可以**手动预置 MinGW64 安装包**，实现零下载编译。

依据 Nuitka 源码 `nuitka/utils/Download.py`（`getCachedDownload`）：它先判断缓存中 **zip 文件或解压后的 `gcc.exe` 是否存在，任一存在即跳过下载**。所以只需把安装包放到指定路径：

```
%LOCALAPPDATA%\Nuitka\Nuitka\Cache\downloads\gcc\x86_64\15.2.0posix-13.0.0-msvcrt-r6\
  └── winlibs-x86_64-posix-seh-gcc-15.2.0-mingw-w64msvcrt-13.0.0-r6.zip
```

（解压后的目录结构为 `...\15.2.0posix-13.0.0-msvcrt-r6\mingw64\bin\gcc.exe`，直接放解压好的目录同样有效。）

| 要点 | 说明 |
|------|------|
| 目录名 | `15.2.0posix-13.0.0-msvcrt-r6` 是 **winlibs 版本号**，Nuitka 升级后可能变化 |
| 如何获取 | 从一台已成功编译的机器上，把上述 zip 直接拷出来 |
| 体积 | 255 MB，适合网盘 / 附件分发 |
| 分发建议 | 终端用户根本不需要编译——**直接发编译好的 `main.dist` 压缩包更省事**（见「编译产物与验证」） |

`python builds.py --check-env` 会直接告诉你缓存是否已就位。

---

## 参数逐条说明

### 编译与分发

| 参数 | 作用 |
|------|------|
| `--mingw64` | 使用 MinGW64 编译器（Nuitka 自动下载官方版本） |
| `--zig` | 使用 Zig 编译器（经 PyPI 获取，不经 GitHub），与 `--mingw64` **二选一** |
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
> （`builds.py` 自身不参与编译，不受影响。）

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

### 分发方式

| 方式 | 适合场景 | 说明 |
|------|---------|------|
| 直接发 `main.dist/` 文件夹 | 内部 / 朋友之间 | 压缩成 zip（约几十 MB）即可 |
| 发 GitHub Release 附件 | 公开发布 | 把 `main.dist/` 压缩后作为 Release 资产上传，用户下载解压即用 |

> **终端用户不需要编译。** 只有想改代码的开发者才需要走完本指南；普通用户拿到 `main.dist` 压缩包解压即可运行。

### 验证清单

1. 双击 `main.dist\PEInspector.exe`，确认窗口正常出现、主题正常加载（无 `FileNotFoundError`）。
2. 在**干净机器或虚拟机**上测试（本机因已装 Python 可能"假正常"）。
3. 测试边界场景：非 PE 文件、损坏文件、超大文件、空文件。
4. 确认用 `sys.exit()` 而非 `exit()`（`no_site` 会导致后者报 `NameError`）。
5. **若换了 `--zig` 后端编译，以上 1–4 项需重新走一遍。**

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
| **首次编译卡在下载** | 正在下载 255 MB 编译器 | 全自动模式会自动测速并择优；手动排查用 `python builds.py --test-net`，再按「网络受限：两条路线」处理 |
| **测速很快但编译时下载失败** | 加速器中途被关闭，或代理不稳定 | 编译全程保持加速器状态不变；或 `--backend zig` 走 PyPI |
| **已装 gcc 却仍要下载** | Nuitka 只认自己下载的 winlibs | 正常现象；在意的话走「兜底：预置编译器包」 |
| **`--zig` 报错** | Zig 是较新后端 | 退回 `--backend mingw64`；或先确认 pip 能正常访问 PyPI |
| **`builds.py` 提示找不到 main.py** | 入口文件尚未创建 | 先完成 `main.py` 再编译 |

### 排查利器

| 手段 | 用途 |
|------|------|
| `python builds.py --check-env` | 一键确认 Python 版本、Nuitka、编译器缓存与网络/代理状态 |
| `python builds.py --test-net` | 网络诊断 + 实测 GitHub / PyPI 下载速度（不用 ping） |
| `python builds.py --dry-run` | 先看会执行什么命令 |
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
- [GitHub520（hosts 加速项目）](https://github.com/521xueweihan/GitHub520)

> 参数核对方式：`python -m nuitka --help` / `--version`（本地 4.2.1 实测）、Nuitka 源码
> `nuitka/plugins/standard/TkinterPlugin.py`、`nuitka/plugins/Plugins.py`、`nuitka/plugins/PluginBase.py`、
> `nuitka/utils/Download.py`、`nuitka/utils/PrivatePipSpace.py`
> 与 `standard.nuitka-package.config.yml`。
>
> 实测记录：MinGW64 安装包 255 MB、`ziglang` wheel 94.1 MB（解压后 381 MB）、
> GitHub 直连测速 0.57 MB/s（2026-09-16）。
