"""PE 解析的数据结构层：dataclass、异常与跨模块共享状态。

本模块**不依赖** pe_parser 其它子模块（依赖链最底层），只放：
- ``PeParseError``：解析失败的统一异常（含中文文案与退出码）
- 各解析结果的 dataclass（ImportSymbol / SectionInfo / PeReport 等）
- ``LOAD_WARNINGS``：外置词典/翻译表加载期的降级告警收集器

拆分自原 achieve/pe_parser.py（2026-10-18，单文件 1728 行 → 按职责拆分）。
``achieve/pe_parser.py`` 仍 re-export 本模块全部公开符号，向后兼容。
"""

from __future__ import annotations

from dataclasses import dataclass, field

# --------------------------------------------------------------------------
# 加载期告警：以 (i18n_key, kwargs) 形式记录，避免"静默降级"。
# 由词典加载模块（pe_translations / pe_risks / pe_dlls）append，
# 最终由 pe_parser._build_report 翻译后并入 report.warnings。
# 放本模块是为让多个加载器共享同一个列表而不产生循环依赖。
# --------------------------------------------------------------------------
LOAD_WARNINGS: list[tuple[str, dict]] = []


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
    meaning: str = ""           # DLL 用途说明（来自 assets/dll_meanings.json，可能为空）


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
    perms_zh: str               # 权限含义（随当前语言，如 "代码·可执行·可读"）
    is_suspicious: bool         # entropy > ENTROPY_WARN
    entropy_sampled: bool = False  # True = 该熵值是采样估算（节区过大，非全量）
    suspicious_reasons: list[str] = field(default_factory=list)  # A5：属性异常原因（随语言）


@dataclass
class RiskyImport:
    """高危 API 导入：分类、风险等级、简要说明。

    注意：``category`` 与 ``risk_level`` 是**数据值**（恒为中文），
    展示层用 translate("RISK_CATEGORY", ...) / i18n t("risk.<等级>") 翻译。
    """

    dll: str
    function: str
    category: str               # 如 "进程注入" / "网络"（数据值，不翻译）
    risk_level: str             # "严重" / "中等" / "低"（数据值，不翻译）
    description: str            # 中文说明


@dataclass
class PackerHit:
    """命中的打包器特征。``name`` 是品牌名（不翻译），证据分节区与字符串两类。"""
    name: str
    sections: list[str] = field(default_factory=list)   # 命中的节区名
    strings: list[str] = field(default_factory=list)     # 命中的特征字符串


@dataclass
class DebugInfo:
    """调试目录条目（A4）。仅 CodeView（debug_type==2）携带 PDB 路径 / GUID / Age。"""
    debug_type: int          # IMAGE_DEBUG_TYPE_* 原始值
    type_text: str             # 类型含义（随语言，如 "CodeView 代码视图"）
    pdb_path: str            # 去尾部 \x00 解码后的完整路径，无则 ""
    pdb_name: str            # 仅文件名（从 pdb_path 提取），无则 ""
    guid: str                # 形如 A56CEAAB-52D1-4269-8EE2-A32D59F492AC，无则 ""
    age: int                 # 无则 0
    timestamp: int           # 调试信息自身的时间戳
    cv_signature: str        # "RSDS" / "NB10" / ""


# 签名状态取值
SIG_NONE = "none"
SIG_VALID = "valid"
SIG_INVALID = "invalid"
SIG_UNKNOWN = "unknown"

# 签名类别（kind）：嵌入式证书 vs 操作系统目录签名（catalog-signed）
SIG_KIND_NONE = "none"           # 无签名
SIG_KIND_EMBEDDED = "embedded"   # 内嵌 PKCS#7 证书（IMAGE_DIRECTORY_ENTRY_SECURITY 非空）
SIG_KIND_CATALOG = "catalog"     # 仅目录签名（内嵌 Security 目录为空，由系统 .cat 提供）


@dataclass
class SignatureInfo:
    """数字签名信息。status 取值见 SIG_* 常量；kind 取值见 SIG_KIND_* 常量。

    关键：``present=True`` 表示**至少在 Windows 层面**该 PE 已被认为「已签名」——
    包括内嵌签名与目录签名（catalog-signed）。仅当签名校验报告无效或不可用，
    且内嵌 Security 目录也为空时，``present=False``。

    ``size`` 是 Security 数据目录的**声明大小**（含 8 字节 WIN_CERTIFICATE 头），
    不是实际 PKCS#7 blob 长度。
    """

    present: bool = False
    status: str = SIG_NONE
    kind: str = SIG_KIND_NONE     # 签名类别，见 SIG_KIND_*
    signer: str = ""
    issuer: str = ""
    detail: str = ""            # 失败原因 / 错误码
    size: int = 0               # 签名数据目录大小（字节，含 WIN_CERTIFICATE 头）


@dataclass
class PeReport:
    """一次解析的完整结果。GUI / CLI / 报告导出三者共用的唯一数据结构。"""

    path: str
    file_size: int
    magic: int
    kind: str
    bits: int
    machine: int
    machine_name: str
    machine_zh: str              # 架构说明（随当前语言）
    subsystem: int
    subsystem_name: str
    subsystem_zh: str            # 子系统说明（随当前语言）
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
    packers: list[PackerHit] = field(default_factory=list)  # 命中的打包器特征
    signature: SignatureInfo = field(default_factory=SignatureInfo)  # 数字签名
    has_imports: bool = False
    has_exports: bool = False
    has_risky_imports: bool = False
    has_packers: bool = False
    suspicious_sections: bool = False
    suspicious_section_count: int = 0   # A5：属性异常的节区个数
    debug_entries: list[DebugInfo] = field(default_factory=list)  # A4：调试目录条目
    has_pdb: bool = False                       # 是否含至少一条可用 PDB 路径
    pdb_paths: list[str] = field(default_factory=list)  # 便于导出/检索
    lang: str = "zh"             # 生成本报告时使用的语言
    warnings: list[str] = field(default_factory=list)
