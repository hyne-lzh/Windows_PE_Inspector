"""高危 API 词典：内置兜底 + 外置 assets/high_risk_apis.json + 导入表扫描。

词典格式：``{小写函数名: (分类, 风险等级, 说明)}``，等级取值 严重/中等/低。
加载策略与 pe_dlls / pe_translations 一致：外置优先、内置兜底、失败记告警
（不再静默 pass）——分析员必须知道"自定义词条没生效"，否则会把漏报当安全。

拆分自原 achieve/pe_parser.py（2026-10-18）。
"""

from __future__ import annotations

import json
from pathlib import Path

from .pe_models import LOAD_WARNINGS, ImportDLL, RiskyImport

# 外置词典路径（项目根 assets/ 下）
RISK_DICT_PATH = Path(__file__).resolve().parent.parent / "assets" / "high_risk_apis.json"

# --------------------------------------------------------------------------
# 高危 API 词典（key 用小写，匹配时统一小写化）
# 值：(分类, 风险等级, 说明)
# --------------------------------------------------------------------------

# 内置兜底词典（仅在 assets/high_risk_apis.json 缺失/损坏时启用）
_BUILTIN_HIGH_RISK_APIS: dict[str, tuple[str, str, str]] = {
    # ---- 进程注入（严重）----
    "createremotethread":    ("进程注入", "严重", "在远程进程中创建线程，常用于代码注入"),
    "ntcreatethreadex":      ("进程注入", "严重", "原生层创建远程线程"),
    "virtualallocex":        ("进程注入", "严重", "在远程进程中分配内存"),
    "writeprocessmemory":    ("进程注入", "严重", "写入远程进程内存"),
    "readprocessmemory":     ("进程注入", "严重", "读取远程进程内存"),
    "openprocess":           ("进程注入", "中等", "打开远程进程句柄"),

    # ---- 进程操作 ----
    "terminateprocess":      ("进程操作", "中等", "终止指定进程"),
    "createprocessa":        ("进程操作", "低",   "创建新进程（ANSI）"),
    "createprocessw":        ("进程操作", "低",   "创建新进程（Unicode）"),
    "shellexecutea":         ("进程操作", "低",   "执行外部命令（ANSI）"),
    "shellexecutew":         ("进程操作", "低",   "执行外部命令（Unicode）"),
    "winexec":               ("进程操作", "低",   "执行外部命令"),
    "createprocessasusera":  ("进程操作", "中等", "以其他用户身份创建进程"),
    "createprocessasuserw":  ("进程操作", "中等", "以其他用户身份创建进程"),

    # ---- DLL 操作 ----
    "loadlibrarya":          ("DLL 操作", "中等", "动态加载 DLL（ANSI）"),
    "loadlibraryw":          ("DLL 操作", "中等", "动态加载 DLL（Unicode）"),
    "loadlibraryexa":        ("DLL 操作", "中等", "从指定路径加载 DLL（ANSI）"),
    "loadlibraryexw":        ("DLL 操作", "中等", "从指定路径加载 DLL（Unicode）"),
    "getprocaddress":        ("DLL 操作", "中等", "获取 DLL 函数地址"),
    "getmodulehandlea":      ("DLL 操作", "低",   "获取模块句柄（ANSI）"),
    "getmodulehandlew":      ("DLL 操作", "低",   "获取模块句柄（Unicode）"),
    "ldrloaddll":            ("DLL 操作", "中等", "原生层加载 DLL"),
    "freelibrary":           ("DLL 操作", "低",   "释放 DLL"),
    "freelibraryandexitthread": ("DLL 操作", "严重", "释放 DLL 并退出线程，常用于注入后退出宿主"),

    # ---- 内存操作 ----
    "virtualprotect":        ("内存操作", "中等", "修改内存页面保护属性"),
    "virtualprotectex":      ("内存操作", "中等", "修改远程进程内存保护属性"),
    "virtualalloc":          ("内存操作", "低",   "分配虚拟内存"),
    "virtualfree":           ("内存操作", "低",   "释放虚拟内存"),
    "virtualquery":          ("内存操作", "低",   "查询虚拟内存信息"),
    "heapcreate":            ("内存操作", "低",   "创建堆"),
    "heapalloc":             ("内存操作", "低",   "堆内存分配"),
    "virtualqueryex":        ("内存操作", "低",   "查询远程进程虚拟内存"),

    # ---- 注册表 ----
    "regsetvalueexa":        ("注册表",   "中等", "设置注册表值（ANSI）"),
    "regsetvalueexw":        ("注册表",   "中等", "设置注册表值（Unicode），常用于自启动"),
    "regcreatekeyexa":       ("注册表",   "中等", "创建注册表键（ANSI）"),
    "regcreatekeyexw":       ("注册表",   "中等", "创建注册表键（Unicode）"),
    "regdeletekeya":         ("注册表",   "中等", "删除注册表键（ANSI）"),
    "regdeletekeyw":         ("注册表",   "中等", "删除注册表键（Unicode）"),
    "regdeletevaluea":       ("注册表",   "中等", "删除注册表值（ANSI）"),
    "regdeletevaluew":       ("注册表",   "中等", "删除注册表值（Unicode）"),
    "regopenkeyexa":         ("注册表",   "低",   "打开注册表键（ANSI）"),
    "regopenkeyexw":         ("注册表",   "低",   "打开注册表键（Unicode）"),
    "regenumkeyexa":         ("注册表",   "低",   "枚举注册表子键（ANSI）"),
    "regenumkeyexw":         ("注册表",   "低",   "枚举注册表子键（Unicode）"),

    # ---- 网络 ----
    "internetopena":         ("网络",     "中等", "打开网络连接（ANSI）"),
    "internetopenw":         ("网络",     "中等", "打开网络连接（Unicode）"),
    "internetconnecta":      ("网络",     "中等", "建立网络连接（ANSI）"),
    "internetconnectw":      ("网络",     "中等", "建立网络连接（Unicode）"),
    "httpopenrequesta":      ("网络",     "中等", "发起 HTTP 请求（ANSI）"),
    "httpopenrequestw":      ("网络",     "中等", "发起 HTTP 请求（Unicode）"),
    "httpsendrequesta":      ("网络",     "中等", "发送 HTTP 请求（ANSI）"),
    "httpsendrequestw":      ("网络",     "中等", "发送 HTTP 请求（Unicode）"),
    "urldownloadtofilea":    ("网络",     "严重", "下载文件到本地，常用于落地载荷"),
    "urldownloadtofilew":    ("网络",     "严重", "下载文件到本地，常用于落地载荷"),
    "wsastartup":            ("网络",     "低",   "初始化 Winsock"),
    "socket":                ("网络",     "低",   "创建套接字"),
    "connect":               ("网络",     "低",   "连接远程主机"),
    "send":                  ("网络",     "低",   "发送数据"),
    "recv":                  ("网络",     "低",   "接收数据"),
    "wsaconnect":            ("网络",     "低",   "Winsock 连接"),
    "wsasend":               ("网络",     "低",   "Winsock 发送"),
    "wsarecv":               ("网络",     "低",   "Winsock 接收"),

    # ---- 文件 ----
    "createfilea":           ("文件",     "低",   "打开/创建文件（ANSI）"),
    "createfilew":           ("文件",     "低",   "打开/创建文件（Unicode）"),
    "writefile":             ("文件",     "低",   "写入文件"),
    "readfile":              ("文件",     "低",   "读取文件"),
    "deletefilea":           ("文件",     "低",   "删除文件（ANSI）"),
    "deletefilew":           ("文件",     "低",   "删除文件（Unicode）"),
    "movefilea":             ("文件",     "低",   "移动文件（ANSI）"),
    "movefilew":             ("文件",     "低",   "移动文件（Unicode）"),
    "copyfilea":             ("文件",     "低",   "复制文件（ANSI）"),
    "copyfilew":             ("文件",     "低",   "复制文件（Unicode）"),

    # ---- 加密 ----
    "cryptacquirecontexta":  ("加密",     "低",   "获取加密服务提供者句柄（ANSI）"),
    "cryptacquirecontextw":  ("加密",     "低",   "获取加密服务提供者句柄（Unicode）"),
    "cryptderivekey":        ("加密",     "低",   "从密码派生密钥"),
    "cryptencrypt":          ("加密",     "中等", "加密数据，勒索软件常用"),
    "cryptdecrypt":          ("加密",     "中等", "解密数据"),
    "cryptgenkey":           ("加密",     "中等", "生成密钥对"),

    # ---- 反调试 ----
    "isdebuggerpresent":     ("反调试",   "中等", "检测调试器是否存在"),
    "checkremotedebuggerpresent": ("反调试", "中等", "检测远程调试器"),
    "ntqueryinformationprocess":  ("反调试", "中等", "查询进程信息，可检测调试端口"),
    "outputdebugstringa":    ("反调试",   "低",   "输出调试字符串，可被用于反调试"),
    "ntsetinformationthread": ("反调试",  "中等", "隐藏线程，常用于反调试"),

    # ---- 键盘记录 ----
    "setwindowshookexa":     ("键盘记录", "严重", "安装钩子，常用于键盘记录"),
    "setwindowshookexw":     ("键盘记录", "严重", "安装钩子，常用于键盘记录"),
    "getasynckeystate":      ("键盘记录", "中等", "查询按键状态"),
    "getkeystate":           ("键盘记录", "中等", "查询按键状态"),
    "getkeyboardstate":      ("键盘记录", "中等", "获取键盘状态"),

    # ---- 屏幕截图 ----
    "bitblt":                ("屏幕截图", "中等", "位块传输，常用于截屏"),
    "createcompatibledc":    ("屏幕截图", "低",   "创建兼容设备上下文"),
    "getdc":                 ("屏幕截图", "低",   "获取设备上下文"),

    # ---- 自启动 ----
    "regsetvalueexa_run":    ("自启动",   "中等", "（占位：Run 键写入）"),
    "createservicea":        ("自启动",   "中等", "创建系统服务（ANSI）"),
    "createservicew":        ("自启动",   "中等", "创建系统服务（Unicode）"),
    "openservicea":          ("自启动",   "低",   "打开系统服务（ANSI）"),
    "openservicew":          ("自启动",   "低",   "打开系统服务（Unicode）"),
    "startservicea":         ("自启动",   "低",   "启动系统服务（ANSI）"),
    "startservicew":         ("自启动",   "低",   "启动系统服务（Unicode）"),

    # ---- 信息收集 ----
    "getcomputernamea":      ("信息收集", "低",   "获取计算机名（ANSI）"),
    "getcomputernamew":      ("信息收集", "低",   "获取计算机名（Unicode）"),
    "getusernamea":          ("信息收集", "低",   "获取用户名（ANSI）"),
    "getusernamew":          ("信息收集", "低",   "获取用户名（Unicode）"),
    "getsysteminfo":         ("信息收集", "低",   "获取系统信息"),
    "getversionexa":         ("信息收集", "低",   "获取系统版本（ANSI）"),
    "getversionexw":         ("信息收集", "低",   "获取系统版本（Unicode）"),
    "getlocaleinfoa":        ("信息收集", "低",   "获取区域信息（ANSI）"),
    "getlocaleinfow":        ("信息收集", "低",   "获取区域信息（Unicode）"),

    # ---- 凭据窃取 ----
    "credreada":             ("凭据窃取", "严重", "读取凭据（ANSI）"),
    "credreadw":             ("凭据窃取", "严重", "读取凭据（Unicode）"),
    "credwritea":            ("凭据窃取", "中等", "写入凭据（ANSI）"),
    "credwritew":            ("凭据窃取", "中等", "写入凭据（Unicode）"),
    "lsaopenpolicy":         ("凭据窃取", "中等", "打开 LSA 策略"),
    "lsaretrieveprivatedata": ("凭据窃取", "严重", "检索 LSA 私密数据"),

    # ---- 防御规避 ----
    "amsiinitialize":        ("防御规避", "严重", "初始化 AMSI，恶意软件常尝试绕过"),
    "ntunmapviewofsection":  ("防御规避", "严重", "卸载进程内存视图，常用于进程镂空"),
    "shellexecuteexa":       ("防御规避", "低",   "执行外部命令（扩展，ANSI）"),
    "shellexecuteexw":       ("防御规避", "低",   "执行外部命令（扩展，Unicode）"),

    # ---- 内核 / 驱动 ----
    "ntloaddriver":          ("驱动加载", "严重", "原生层加载驱动"),
    "ntquerysysteminformation": ("内核操作", "中等", "查询系统信息，可枚举模块/句柄"),
    "iocreatefilesynchronize": ("内核操作", "低",  "创建同步文件对象"),
}


def _load_high_risk_apis() -> dict[str, tuple[str, str, str]]:
    """从 assets/high_risk_apis.json 加载高危 API 词典。

    加载失败时**记录告警并回退内置**（不再静默 pass）。
    """
    try:
        with RISK_DICT_PATH.open(encoding="utf-8") as fh:
            raw = json.load(fh)
    except FileNotFoundError:
        LOAD_WARNINGS.append(("warn.risk_missing", {}))
        return dict(_BUILTIN_HIGH_RISK_APIS)
    except (OSError, json.JSONDecodeError) as exc:
        LOAD_WARNINGS.append(("warn.risk_load_failed", {"err": exc}))
        return dict(_BUILTIN_HIGH_RISK_APIS)

    loaded: dict[str, tuple[str, str, str]] = {}
    if isinstance(raw, dict):
        for key, val in raw.items():
            if isinstance(val, (list, tuple)) and len(val) == 3:
                loaded[str(key).lower()] = (str(val[0]), str(val[1]), str(val[2]))
    if loaded:
        return loaded
    # 外置文件存在但一条都没解析出来：视为损坏，回退内置并告警
    LOAD_WARNINGS.append(("warn.risk_empty", {}))
    return dict(_BUILTIN_HIGH_RISK_APIS)


# 实际生效的词典（外部 JSON 优先，内置条目兜底）
HIGH_RISK_APIS: dict[str, tuple[str, str, str]] = _load_high_risk_apis()


def _scan_risky_imports(imports: list[ImportDLL]) -> list[RiskyImport]:
    """扫描导入表，匹配高危 API 词典。

    同一函数被多个 DLL 导入会产生多条记录（各自带来源 DLL），这是有意的——
    分析员需要知道"哪个 DLL 引用了这个危险函数"。
    """
    risky: list[RiskyImport] = []
    for dll in imports:
        for sym in dll.symbols:
            name = sym.display
            key = name.lower()
            if key in HIGH_RISK_APIS:
                category, risk_level, description = HIGH_RISK_APIS[key]
                risky.append(RiskyImport(
                    dll=dll.dll,
                    function=name,
                    category=category,
                    risk_level=risk_level,
                    description=description,
                ))
    return risky
