"""PE 解析核心：数据结构 + 纯解析逻辑。

只依赖 pefile 与标准库；**禁止 import customtkinter / tkinter**。
解析入口 parse_pe() 返回 PeReport，供命令行与图形界面共用（单一真相源）。
"""

from __future__ import annotations

import datetime
import json
import math
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

import pefile

from .strings_extractor import classify_strings, extract_strings

# 节区熵值超过该阈值即提示"疑似加壳/加密"（8.0 为理论上限）
ENTROPY_WARN = 7.2

# 采样熵：节区原始数据超过该阈值时改用采样估算（全量算熵在大文件上很慢）
ENTROPY_SAMPLE_THRESHOLD = 50 * 1024 * 1024   # 50 MB 以上走采样
ENTROPY_SAMPLE_SIZE = 4 * 1024 * 1024          # 采样 4 MB

# 安全上限：超过该大小直接拒绝解析（本工具要面对恶意样本，不能让它耗尽内存）
MAX_FILE_SIZE = 2 * 1024 * 1024 * 1024        # 2 GB

# 节区特征位（挑常用的）
SECTION_FLAGS = (
    (0x00000020, "CODE"),
    (0x00000040, "IDATA"),
    (0x00000080, "UDATA"),
    (0x20000000, "X"),
    (0x40000000, "R"),
    (0x80000000, "W"),
)

# 节区权限缩写 → 中文含义
PERMISSION_TRANSLATIONS = {
    "CODE": "代码",
    "IDATA": "已初始化数据",
    "UDATA": "未初始化数据",
    "X": "可执行",
    "R": "可读",
    "W": "可写",
}


class PeParseError(Exception):
    """解析失败。message 是面向用户的中文文案；exit_code 供命令行返回。"""

    def __init__(self, message: str, exit_code: int = 1) -> None:
        super().__init__(message)
        self.exit_code = exit_code


@dataclass
class ImportSymbol:
    name: str | None            # 有名导入
    ordinal: int | None         # 序号导入（name 为 None 时使用）

    @property
    def display(self) -> str:
        return self.name or f"Ordinal#{self.ordinal}"


@dataclass
class ImportDLL:
    dll: str
    symbols: list[ImportSymbol] = field(default_factory=list)


@dataclass
class ExportSymbol:
    ordinal: int
    rva: int
    name: str | None            # None 表示"(仅序号)"
    forwarder: str | None       # None 表示无转发


@dataclass
class SectionInfo:
    name: str                   # 解码失败或为空 → "(无名)"
    virtual_size: int
    raw_size: int
    entropy: float
    characteristics: int
    perms: str                  # 缩写如 "CODEXR"
    perms_zh: str               # 中文含义如 "代码·可执行·可读"
    is_suspicious: bool         # entropy > ENTROPY_WARN
    entropy_sampled: bool = False  # True = 该熵值是采样估算（节区过大，非全量）


@dataclass
class RiskyImport:
    """高危 API 导入：分类、风险等级、简要说明。"""
    dll: str
    function: str
    category: str               # 如 "进程注入" / "网络"
    risk_level: str             # "严重" / "中等" / "低"
    description: str            # 中文说明


@dataclass
class PeReport:
    path: str
    file_size: int
    magic: int
    kind: str
    bits: int
    machine: int
    machine_name: str
    subsystem: int
    subsystem_name: str
    time_date_stamp: int
    compile_time_text: str
    time_in_future: bool
    entry_point_rva: int
    image_base: int
    checksum: int
    num_sections: int
    num_data_directories: int
    sections: list[SectionInfo] = field(default_factory=list)
    imports: list[ImportDLL] = field(default_factory=list)
    exports: list[ExportSymbol] = field(default_factory=list)
    risky_imports: list[RiskyImport] = field(default_factory=list)
    strings_summary: dict = field(default_factory=dict)  # extract_strings 完整结果（含来源/失败原因）
    string_count: int = 0                                # 合并去重后的字符串总数
    string_classes: dict = field(default_factory=dict)   # classify_strings 分类结果
    has_imports: bool = False
    has_exports: bool = False
    has_risky_imports: bool = False
    suspicious_sections: bool = False
    warnings: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------
# 纯格式工具
# --------------------------------------------------------------------------

def human_size(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n / 1024 / 1024:.1f} MB"


def _is_future(stamp: int) -> bool:
    if not stamp:
        return False
    try:
        dt = datetime.datetime.fromtimestamp(stamp, tz=datetime.timezone.utc)
    except (OverflowError, OSError, ValueError):
        return False
    return dt.year > datetime.datetime.now(datetime.timezone.utc).year


def fmt_time(stamp: int) -> str:
    if not stamp:
        return "(未设置)"
    try:
        dt = datetime.datetime.fromtimestamp(stamp, tz=datetime.timezone.utc)
    except (OverflowError, OSError, ValueError):
        return f"(异常值 {stamp})"
    text = dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    if _is_future(stamp):
        text += "  [!] 时间戳位于未来，可能被篡改"
    return text


def section_perms(ch: int) -> str:
    return "".join(name for bit, name in SECTION_FLAGS if ch & bit) or "-"


def perms_to_zh(perms: str) -> str:
    """把权限缩写翻译为中文含义，例如 "CODEXR" → "代码·可执行·可读"。

    按最长优先匹配多字符代码（UDATA 5 字符 > IDATA 5 字符 > CODE 4 字符 > X/R/W 1 字符）。
    """
    if not perms or perms == "-":
        return "-"
    # 按字符长度从长到短排序（UDATA/IDATA 5 > CODE 4 > X/R/W 1），保证贪婪匹配
    codes_by_len = sorted(PERMISSION_TRANSLATIONS.keys(), key=len, reverse=True)
    parts: list[str] = []
    remaining = perms
    while remaining:
        matched = False
        for code in codes_by_len:
            if remaining.startswith(code):
                parts.append(PERMISSION_TRANSLATIONS[code])
                remaining = remaining[len(code):]
                matched = True
                break
        if not matched:
            # 理论上不会发生（section_perms 只产出已知代码），但兜底保留单字符
            parts.append(remaining[0])
            remaining = remaining[1:]
    return "·".join(parts)


# --------------------------------------------------------------------------
# 采样熵（性能：超大节区不再全量计算）
# --------------------------------------------------------------------------

def _entropy_of(data: bytes) -> float:
    """计算字节序列的香农熵（0~8）。与 pefile 的 get_entropy() 算法一致。"""
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    ent = 0.0
    for c in counts.values():
        p = c / total
        ent -= p * math.log2(p)
    return ent


def _sampled_data(data: bytes, sample_size: int) -> bytes:
    """从大块数据里采样：取头、中、尾三段各 sample_size/3，兼顾代表性与速度。"""
    if len(data) <= sample_size:
        return data
    third = max(1, sample_size // 3)
    head = data[:third]
    mid_start = (len(data) - third) // 2
    mid = data[mid_start:mid_start + third]
    tail = data[-third:]
    return head + mid + tail


def section_entropy(section, sample_threshold: int = ENTROPY_SAMPLE_THRESHOLD) -> tuple[float, bool]:
    """计算节区熵值，返回 (熵值, 是否采样)。

    - 节区数据 <= sample_threshold（默认 50 MB）：全量计算，结果精确
    - 超过阈值：改用 4 MB 采样估算，避免大文件上几十秒的卡顿
    """
    try:
        data = section.get_data()
    except Exception:  # noqa: BLE001
        # get_data 可能失败（如 SizeOfRawData 为 0），回退到 pefile 自带实现
        try:
            return float(section.get_entropy()), False
        except Exception:  # noqa: BLE001
            return 0.0, False

    if len(data) > sample_threshold:
        return _entropy_of(_sampled_data(data, ENTROPY_SAMPLE_SIZE)), True
    return _entropy_of(data), False


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
    "regenumkeyexa":         ("注册表",   "低",   "枚举注册表子键（Unicode）"),

    # ---- 网络 ----
    "wsastartup":            ("网络",     "中等", "初始化 Winsock"),
    "socket":                ("网络",     "中等", "创建套接字"),
    "connect":               ("网络",     "中等", "连接远程地址"),
    "send":                  ("网络",     "中等", "发送数据"),
    "recv":                  ("网络",     "中等", "接收数据"),
    "internetopena":         ("网络",     "中等", "初始化 WinINet（ANSI）"),
    "internetopenw":         ("网络",     "中等", "初始化 WinINet（Unicode）"),
    "internetconnecta":      ("网络",     "中等", "连接服务器（ANSI）"),
    "internetconnectw":      ("网络",     "中等", "连接服务器（Unicode）"),
    "httpsendrequesta":      ("网络",     "中等", "发送 HTTP 请求（ANSI）"),
    "httpsendrequestw":      ("网络",     "中等", "发送 HTTP 请求（Unicode）"),
    "urldownloadtofilea":    ("网络",     "严重", "下载文件到本地（ANSI），常用于木马下载"),
    "urldownloadtofilew":    ("网络",     "严重", "下载文件到本地（Unicode），常用于木马下载"),
    "inetntoa":              ("网络",     "低",   "IP 地址转字符串"),
    "gethostbyname":         ("网络",     "中等", "域名解析为 IP"),
    "dnsquery":              ("网络",     "中等", "DNS 查询"),
    "sendto":                ("网络",     "中等", "UDP 发送数据"),

    # ---- 文件 ----
    "createfilea":           ("文件",     "低",   "创建/打开文件（ANSI）"),
    "createfilew":           ("文件",     "低",   "创建/打开文件（Unicode）"),
    "writefile":             ("文件",     "低",   "写入文件"),
    "readfile":              ("文件",     "低",   "读取文件"),
    "deletefilea":           ("文件",     "中等", "删除文件（ANSI）"),
    "deletefilew":           ("文件",     "中等", "删除文件（Unicode）"),
    "movefilea":             ("文件",     "低",   "移动文件（ANSI）"),
    "movefilew":             ("文件",     "低",   "移动文件（Unicode）"),
    "copyfilea":             ("文件",     "低",   "复制文件（ANSI）"),
    "copyfilew":             ("文件",     "低",   "复制文件（Unicode）"),
    "createprocessinternala": ("文件",    "中等", "原生层创建进程（ANSI）"),
    "createprocessinternalw": ("文件",    "中等", "原生层创建进程（Unicode）"),

    # ---- 加密 ----
    "cryptacquirecontexta":  ("加密",     "低",   "获取加密上下文（ANSI）"),
    "cryptacquirecontextw":  ("加密",     "低",   "获取加密上下文（Unicode）"),
    "cryptgenrandom":        ("加密",     "低",   "生成随机数"),
    "cryptencrypt":          ("加密",     "低",   "加密数据"),
    "cryptdecrypt":          ("加密",     "低",   "解密数据"),
    "crypthashdata":         ("加密",     "低",   "计算哈希"),

    # ---- 反调试（严重）----
    "isdebuggerpresent":            ("反调试", "严重", "检测当前进程是否被调试"),
    "checkremotedebuggerpresent":   ("反调试", "严重", "检测远程调试器"),
    "ntqueryinformationprocess":    ("反调试", "中等", "查询进程信息，常用于反调试"),
    "queryperformancecounter":      ("反调试", "中等", "性能计数器，常用于反调试时间检测"),
    "gettickcount":                 ("反调试", "低",   "获取系统启动毫秒数"),
    "ntquerysysteminformation":     ("反调试", "中等", "查询系统信息"),
    "rtladjustprivilege":           ("反调试", "严重", "提权操作"),
    "ntsetinformationprocess":      ("反调试", "严重", "设置进程信息"),
    "zwqueryinformationprocess":    ("反调试", "中等", "原生层查询进程信息"),
    "findwindowa":                  ("反调试", "中等", "查找窗口（ANSI），常用于检测调试器窗口"),
    "findwindoww":                  ("反调试", "中等", "查找窗口（Unicode）"),

    # ---- 键盘记录（严重）----
    "setwindowshookexa":            ("键盘记录", "严重", "设置全局钩子（ANSI），常用于键盘记录"),
    "setwindowshookexw":            ("键盘记录", "严重", "设置全局钩子（Unicode），常用于键盘记录"),
    "getasynckeystate":             ("键盘记录", "严重", "获取异步按键状态，常用于键盘记录"),
    "getkeystate":                  ("键盘记录", "中等", "获取按键状态"),
    "registerhotkey":               ("键盘记录", "中等", "注册全局热键"),

    # ---- 屏幕截图 ----
    "bitblt":                       ("屏幕截图", "中等", "位图复制，可用于屏幕截图"),
    "createcompatiblebitmap":       ("屏幕截图", "中等", "创建兼容位图"),
    "getdesktopwindow":             ("屏幕截图", "低",   "获取桌面窗口句柄"),
    "getdc":                        ("屏幕截图", "低",   "获取设备上下文"),
    "getwindowdc":                  ("屏幕截图", "低",   "获取窗口设备上下文"),
    "keybd_event":                  ("屏幕截图", "中等", "模拟键盘事件"),
    "mouse_event":                  ("屏幕截图", "中等", "模拟鼠标事件"),
    "printwindow":                  ("屏幕截图", "中等", "打印窗口内容，可用于截图"),

    # ---- 自启动 / 持久化 ----
    "createtoolhelp32snapshot":     ("自启动",   "中等", "创建进程快照，用于枚举进程"),
    "adjusttokenprivileges":        ("自启动",   "严重", "调整令牌权限，常用于提权"),
    "createservicea":               ("自启动",   "严重", "创建系统服务（ANSI），常用于持久化"),
    "createservicew":               ("自启动",   "严重", "创建系统服务（Unicode），常用于持久化"),
    "openscmanagera":               ("自启动",   "中等", "打开服务控制管理器（ANSI）"),
    "openscmanagerw":               ("自启动",   "中等", "打开服务控制管理器（Unicode）"),
    "startservicea":                ("自启动",   "中等", "启动系统服务（ANSI）"),
    "startservicew":                ("自启动",   "中等", "启动系统服务（Unicode）"),
    "createprocesswithlogonw":      ("自启动",   "中等", "使用其他凭据创建进程"),
}


# 外置词典路径（项目根 assets/ 下，用户可自行编辑扩充，无需改代码）
RISK_DICT_PATH = Path(__file__).resolve().parent.parent / "assets" / "high_risk_apis.json"


def _load_high_risk_apis() -> dict[str, tuple[str, str, str]]:
    """从 assets/high_risk_apis.json 加载高危 API 词典。

    外置的目的：让用户能自行编辑/扩充词条，不必改动 Python 代码。
    加载失败（文件缺失、格式错误）时回退到内置条目，保证功能不残废。
    """
    try:
        with RISK_DICT_PATH.open(encoding="utf-8") as fh:
            raw = json.load(fh)
        loaded: dict[str, tuple[str, str, str]] = {}
        for key, val in raw.items():
            if isinstance(val, (list, tuple)) and len(val) == 3:
                loaded[str(key).lower()] = (str(val[0]), str(val[1]), str(val[2]))
        if loaded:
            return loaded
    except Exception:  # noqa: BLE001
        pass
    return dict(_BUILTIN_HIGH_RISK_APIS)


# 实际生效的词典（外部 JSON 优先，内置条目兜底）
HIGH_RISK_APIS: dict[str, tuple[str, str, str]] = _load_high_risk_apis()


def _scan_risky_imports(imports: list[ImportDLL]) -> list[RiskyImport]:
    """扫描导入表，匹配高危 API 词典。"""
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


# --------------------------------------------------------------------------
# 解析
# --------------------------------------------------------------------------

def parse_pe(path) -> PeReport:
    """解析 PE 文件，失败时抛 PeParseError（含中文文案与退出码）。

    安全约束（审查项，不可回退）：
    - **无论解析在哪一步失败，都保证 pe.close() 被执行**，句柄不泄漏
    - **所有异常统一翻译为 PeParseError**，避免调用方（CLI/GUI）收到裸 traceback
    - 超过 MAX_FILE_SIZE 的文件直接拒绝，防止恶意大文件耗尽内存
    """
    pe = None
    try:
        p = Path(path).expanduser()
        if not p.is_file():
            raise PeParseError(f"文件不存在：{p}", exit_code=1)

        size = p.stat().st_size
        if size > MAX_FILE_SIZE:
            raise PeParseError(
                f"文件过大（{human_size(size)} > {human_size(MAX_FILE_SIZE)}），已拒绝解析",
                exit_code=1,
            )

        pe = pefile.PE(str(p), fast_load=True)
        pe.parse_data_directories(
            directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
            ]
        )
        return _build_report(pe, p)
    except PeParseError:
        raise
    except pefile.PEFormatError as exc:
        raise PeParseError(f"不是有效的 PE 文件：{exc}", exit_code=2) from exc
    except OSError as exc:
        raise PeParseError(f"无法读取文件：{exc}", exit_code=1) from exc
    except Exception as exc:  # noqa: BLE001
        # 畸形 PE 会触发 pefile 内部各种异常（struct.error / ValueError 等），
        # 统一兜住，绝不裸抛给调用方——CLI 会 traceback，GUI 会闪退。
        raise PeParseError(
            f"PE 结构异常，解析已中止：{type(exc).__name__}: {exc}", exit_code=2
        ) from exc
    finally:
        if pe is not None:
            try:
                pe.close()
            except Exception:  # noqa: BLE001
                pass


def _build_report(pe: pefile.PE, p: Path) -> PeReport:
    fh = pe.FILE_HEADER
    oh = pe.OPTIONAL_HEADER

    magic = int(oh.Magic)
    kind = {0x10B: "PE32 (32 位)", 0x20B: "PE32+ (64 位)"}.get(magic, "未知")
    bits = 64 if magic == 0x20B else 32
    stamp = int(fh.TimeDateStamp)

    sections: list[SectionInfo] = []
    for s in pe.sections:
        name = s.Name.rstrip(b"\x00").decode("utf-8", errors="replace") or "(无名)"
        entropy, sampled = section_entropy(s)
        perms = section_perms(int(s.Characteristics))
        sections.append(
            SectionInfo(
                name=name,
                virtual_size=int(s.Misc_VirtualSize),
                raw_size=int(s.SizeOfRawData),
                entropy=entropy,
                characteristics=int(s.Characteristics),
                perms=perms,
                perms_zh=perms_to_zh(perms),
                is_suspicious=entropy > ENTROPY_WARN,
                entropy_sampled=sampled,
            )
        )

    imports: list[ImportDLL] = []
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", None) or []:
        dll = entry.dll.decode("utf-8", errors="replace")
        symbols: list[ImportSymbol] = []
        for imp in entry.imports:
            if imp.name:
                symbols.append(
                    ImportSymbol(
                        name=imp.name.decode("utf-8", errors="replace"),
                        ordinal=None,
                    )
                )
            else:
                symbols.append(ImportSymbol(name=None, ordinal=int(imp.ordinal)))
        imports.append(ImportDLL(dll=dll, symbols=symbols))

    risky_imports = _scan_risky_imports(imports)

    # 字符串提取：strings.exe（外部工具）+ pefile（兜底）双重来源
    strings_summary = extract_strings(str(p), min_length=5)
    merged_strings = strings_summary.get("merged", [])
    string_classes = classify_strings(merged_strings)

    exports: list[ExportSymbol] = []
    exp = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    if exp and exp.symbols:
        for sym in exp.symbols:
            exports.append(
                ExportSymbol(
                    ordinal=int(sym.ordinal),
                    rva=int(sym.address),
                    name=sym.name.decode("utf-8", errors="replace") if sym.name else None,
                    forwarder=sym.forwarder.decode("utf-8", errors="replace") if sym.forwarder else None,
                )
            )

    warnings: list[str] = []
    if p.stat().st_size > 200 * 1024 * 1024:
        warnings.append("文件较大（>200 MB），解析可能耗时较长")

    return PeReport(
        path=str(p),
        file_size=int(p.stat().st_size),
        magic=magic,
        kind=kind,
        bits=bits,
        machine=int(fh.Machine),
        machine_name=str(pefile.MACHINE_TYPE.get(fh.Machine, hex(fh.Machine))),
        subsystem=int(oh.Subsystem),
        subsystem_name=str(pefile.SUBSYSTEM_TYPE.get(oh.Subsystem, str(oh.Subsystem))),
        time_date_stamp=stamp,
        compile_time_text=fmt_time(stamp),
        time_in_future=_is_future(stamp),
        entry_point_rva=int(oh.AddressOfEntryPoint),
        image_base=int(oh.ImageBase),
        checksum=int(oh.CheckSum),
        num_sections=int(fh.NumberOfSections),
        num_data_directories=int(oh.NumberOfRvaAndSizes),
        sections=sections,
        imports=imports,
        exports=exports,
        risky_imports=risky_imports,
        strings_summary=strings_summary,
        string_count=len(merged_strings),
        string_classes=string_classes,
        has_imports=bool(imports),
        has_exports=bool(exports),
        has_risky_imports=bool(risky_imports),
        suspicious_sections=any(s.is_suspicious for s in sections),
        warnings=warnings,
    )
