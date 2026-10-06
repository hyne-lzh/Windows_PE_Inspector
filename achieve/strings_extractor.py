"""字符串提取模块（Windows PE Inspector）。

本模块提供对 PE 文件（以及任意二进制文件）的字符串「双重来源」提取能力：

  1. 外部工具 strings.exe（Sysinternals Strings）优先：速度快、覆盖 ASCII + Unicode；
  2. pefile 正则兜底：当 strings.exe 不可用 / 超时 / 报错时，静默回退到对
     各节区原始数据做正则扫描，保证「绝不抛异常给调用方」。

设计要点
--------
- 外部工具优先、失败自动回退：调用方无需关心底层来源，拿到的永远是
  {"external", "pefile", "merged", "source", "external_ok", "error"} 这个统一结构；
- 所有异常（FileNotFoundError / TimeoutExpired / SubprocessError / OSError 等）
  均被捕获并按需回退，本模块不会把异常抛给上层；
- 仅依赖标准库 + pefile，不引入任何新的第三方依赖；
- 纯静态解析，绝不运行样本；
- 模块内置可选的分类函数 classify_strings()，可把字符串按可疑类型归桶，
  便于 GUI / 命令行直接展示 IOC 线索。

对外接口
--------
- extract_strings(path, min_length=4, use_external=True, timeout=30, strings_exe=None) -> dict
- classify_strings(strings, known_apis=None, known_sections=None) -> dict
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

try:
    import pefile
except ImportError:  # pragma: no cover - 运行环境已预装 pefile
    pefile = None  # type: ignore


# strings.exe 位于项目根目录（achieve 目录的上一级）。
_DEFAULT_STRINGS_EXE = Path(__file__).resolve().parent.parent / "strings.exe"


def _find_strings_exe(custom_path=None):
    """解析 strings.exe 路径；找不到返回 None（交由上层回退到 pefile）。"""
    if custom_path:
        p = Path(custom_path)
        if p.is_file():
            return p
        return None
    return _DEFAULT_STRINGS_EXE if _DEFAULT_STRINGS_EXE.is_file() else None


def _decode_bytes(raw: bytes) -> str:
    """用与运行环境一致的编码解码；失败处用替换字符，绝不抛异常。"""
    enc = getattr(sys.stdout, "encoding", None) or "utf-8"
    try:
        return raw.decode(enc, errors="replace")
    except (LookupError, UnicodeError):
        return raw.decode("utf-8", errors="replace")


def _run_strings_exe(path, min_length, timeout, strings_exe):
    """调用 strings.exe 提取字符串。

    返回 (字符串列表, 错误信息|None)。任何失败都通过 error 文本表达，
    不向外抛出。
    """
    exe = _find_strings_exe(strings_exe)
    if exe is None:
        return [], "strings.exe 未找到（已回退到 pefile）"

    try:
        proc = subprocess.run(
            [str(exe), "-nobanner", "-n", str(min_length), str(path)],
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        return [], "strings.exe 未找到（已回退到 pefile）"
    except subprocess.TimeoutExpired:
        return [], "strings.exe 执行超时（已回退到 pefile）"
    except (subprocess.SubprocessError, OSError) as exc:
        return [], f"strings.exe 执行失败：{exc}（已回退到 pefile）"
    except Exception as exc:  # 兜底，保护调用方
        return [], f"strings.exe 未知异常：{exc}（已回退到 pefile）"

    if proc.returncode != 0:
        err = _decode_bytes(proc.stderr or b"").strip()
        return [], f"strings.exe 退出码 {proc.returncode}" + (f"：{err}" if err else "")

    out = _decode_bytes(proc.stdout or b"")
    # 每行一个字符串；丢弃空行（banner 已由 -nobanner 去除，但保险起见过滤）
    lines = [ln for ln in out.splitlines() if ln != ""]
    return lines, None


def _pefile_extract(path, min_length):
    """用 pefile 对各节区原始数据做正则扫描，作为兜底来源。

    任何失败都返回空列表，不抛异常。
    """
    if pefile is None:
        return []

    results: list[str] = []
    n = max(1, int(min_length))
    try:
        pe = pefile.PE(path, fast_load=True)
    except Exception:
        return []

    try:
        ascii_re = re.compile(rb"[\x20-\x7e]{" + str(n).encode() + rb",}")
        uni_re = re.compile(rb"(?:[\x20-\x7e]\x00){" + str(n).encode() + rb",}")
        sections = getattr(pe, "sections", None) or []
        for section in sections:
            try:
                data = section.get_data()
            except Exception:
                continue
            if not data:
                continue
            for m in ascii_re.finditer(data):
                results.append(m.group().decode("ascii", errors="replace"))
            for m in uni_re.finditer(data):
                try:
                    results.append(m.group().decode("utf-16-le"))
                except Exception:
                    pass
    except Exception:
        pass
    finally:
        try:
            pe.close()
        except Exception:
            pass

    # 节内/节间可能重复，按首次出现顺序去重
    return list(dict.fromkeys(results))


def extract_strings(path, min_length=4, use_external=True, timeout=30, strings_exe=None) -> dict:
    """双重来源提取字符串。

    参数
    ----
    path         : 待分析文件路径（PE 或其他二进制文件均可）。
    min_length   : 最小字符串长度（同时传给 strings.exe 的 -n 与 pefile 正则）。
    use_external : 是否优先使用 strings.exe；设为 False 则只用 pefile 兜底。
    timeout      : 调用 strings.exe 的超时秒数（默认 30）。
    strings_exe  : 可选，自定义 strings.exe 路径；None 时用模块内置默认路径。
                   主要用于测试或部署环境差异，不影响默认调用方式。

    返回
    ----
    {
        "external"   : [...],  # strings.exe 提取到的列表（失败则为空）
        "pefile"     : [...],  # pefile 兜底提取到的列表（非 PE/失败则为空）
        "merged"     : [...],  # 合并去重后的列表（保持首次出现顺序）
        "source"     : "strings.exe+pefile" | "pefile",  # 实际使用的来源
        "external_ok": bool,   # 外部工具是否成功
        "error"      : str|None  # 外部工具失败原因（成功则 None）
    }
    """
    result = {
        "external": [],
        "pefile": [],
        "merged": [],
        "source": "pefile",
        "external_ok": False,
        "error": None,
    }

    if not path or not os.path.isfile(path):
        # 文件不存在：pefile 也无法打开，直接返回空并说明
        result["error"] = "文件不存在或不可读"
        return result

    external: list[str] = []
    error: str | None = None
    if use_external:
        external, error = _run_strings_exe(path, min_length, timeout, strings_exe)
    result["external"] = external
    result["external_ok"] = error is None and use_external
    # 仅在主动关闭外部工具时，error 保持 None；否则记录失败原因
    result["error"] = None if (not use_external) else error

    # pefile 始终作为兜底/补充来源参与提取
    result["pefile"] = _pefile_extract(path, min_length)

    result["source"] = "strings.exe+pefile" if result["external_ok"] else "pefile"

    # 合并去重：先外部后 pefile，保持首次出现顺序
    merged = list(dict.fromkeys(result["external"] + result["pefile"]))
    result["merged"] = merged
    return result


# --------------------------------------------------------------------------
# 可选：按可疑类型分类
# --------------------------------------------------------------------------

_URL_RE = re.compile(r"^(https?|ftp)://", re.IGNORECASE)
# 候选 IPv4（四段点分十进制）；再用 _looks_like_ip 校验每段 0-255，
# 过滤 999.x.x.x 这类明显非 IP（版本号 5.1.0.0 仍可能被匹配，属简单正则的已知局限）。
_IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_REG_RE = re.compile(r"HKEY_|HK[A-Z]{2,3}\\|\\Software\\", re.IGNORECASE)
_PATH_RE = re.compile(r"^[A-Za-z]:\\|\\\\")
_PDB_RE = re.compile(r"\.pdb", re.IGNORECASE)

# XML / SxS manifest 片段特征（编译产物噪音，不是 IOC 线索）
_XML_HINTS = (
    "<?xml", "<assembly", "</assembly", "xmlns=", "</dependency",
    "<dependency", "<assemblyidentity", "</assemblyidentity",
    "urn:schemas-microsoft-com", "<trustinfo", "<security",
    "<requestedprivileges", "<requestedexecutionlevel", "<compatibility",
)

# 分类 key 的固定顺序（返回 dict 时 10 个 key 恒存在，没命中也给空列表）
_CLASS_KEYS = ("urls", "ips", "registry", "paths", "pdb",
               "xml", "sections", "dlls", "apis", "others")

# strings.exe 扫不到导入表时可用的常见节区名兜底名单（含加壳器节区）
_DEFAULT_SECTIONS = (
    ".text", ".textbss", ".code", ".rdata", ".rodata", ".data", ".pdata",
    ".didat", ".rsrc", ".reloc", ".tls", ".bss", ".idata", ".edata",
    ".debug", ".crt", ".vmp0", ".vmp1", ".upx0", ".upx1", ".aspack",
    ".nsp0", ".nsp1", ".petite",
)

# 模块名：xxx.dll / xxx.exe / xxx.sys
_DLL_RE = re.compile(r"^[A-Za-z0-9_.\-]+\.(dll|exe|sys)$", re.IGNORECASE)

# known_apis 缺失时的启发式前缀（Win32 / Native / 内核常见动宾前缀）
_API_PREFIXES = (
    "Get", "Set", "Reg", "Create", "Open", "Close", "Find", "Load", "Free",
    "Is", "Nt", "Zw", "Rtl", "Ldr", "Io", "Ke", "Mm", "Ob", "Ps",
    "Global", "Local", "Heap", "Virtual", "Write", "Read", "Delete", "Enum",
    "Query", "Crypt", "Shell", "Send", "Post", "Lsa", "Dbg", "Co", "Cert",
)


def _looks_like_ip(candidate: str) -> bool:
    """校验四段点分十进制每段都在 0-255 之间。"""
    parts = candidate.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit():
            return False
        if not 0 <= int(part) <= 255:
            return False
    return True


def _is_xml_line(s: str) -> bool:
    """判断是否为 XML / SxS manifest 片段（这类内容是编译产物噪音，不算可疑线索）。"""
    low = s.lower()
    if low.lstrip().startswith("<?xml"):
        return True
    return any(h in low for h in _XML_HINTS)


def _strip_noise(s: str) -> str:
    """去掉行首最多 2 个对齐/杂字符（反引号、@ 等），保留 '.' 与 '-'。

    strings.exe 扫节区头时常带 1~2 个对齐字节前缀，例如 `` `.text`` / ``@.data``。
    """
    out = s.strip()
    dropped = 0
    while out and dropped < 2 and not (out[0].isalnum() or out[0] in "._-"):
        out = out[1:]
        dropped += 1
    return out


def _as_lower_set(values) -> set[str]:
    """把任意可迭代对象转成小写字符串集合；非法输入返回空集合，绝不抛异常。"""
    out: set[str] = set()
    try:
        if not values:
            return out
        for v in values:
            if v:
                out.add(str(v).strip().lower())
    except TypeError:
        return out
    except Exception:
        return out
    return out


def _looks_like_api(s: str) -> bool:
    """``known_apis`` 缺失时的启发式判定：纯 CamelCase 标识符 + 常见 WinAPI 前缀。"""
    if len(s) < 6 or not s.isascii() or not s[0].isalpha():
        return False
    ok_chars = all(ch.isalnum() or ch == "_" for ch in s)
    if not ok_chars:
        return False
    if not any(s.startswith(p) for p in _API_PREFIXES):
        return False
    # CamelCase：小写/数字后紧跟大写，如 GetProcAddress / RegSetValueW / NtCreateFile
    return bool(re.search(r"[a-z0-9][A-Z]", s))


def classify_strings(strings: list[str] | None = None,
                     known_apis=None,
                     known_sections=None) -> dict:
    """把字符串按可疑类型分类，返回各类命中列表（10 个 key 恒存在）。

    参数
    ----
    strings        : 待分类的字符串列表（None / 非列表输入按空处理，绝不抛异常）。
    known_apis     : 可选，文件导入表/导出表中的真实函数名集合；提供时 API 分类做
                     精确匹配（不区分大小写），误判率最低。
    known_sections : 可选，文件真实节区名集合（如 ``.text``）；提供时只认这些名字。

    分类优先级（每个字符串仅归入首个匹配类别）：
      urls      : 以 http:// / https:// / ftp:// 开头（容许 1 字节行首噪音，适配 CRL/OCSP 截断）
      ips       : IPv4 点分十进制
      registry  : 含 HKEY_ 或 HKLM\\ / HKCU\\ / Software\\ 等注册表特征
      paths     : Windows 路径（C:\\...）或 UNC（\\\\...）
      pdb       : 含 .pdb（PDB 调试符号路径，常泄露编译机目录）
      xml       : XML / SxS manifest 片段（编译产物噪音）
      sections  : PE 节区名（常带 1~2 个对齐字节前缀）
      dlls      : 形如 xxx.dll / xxx.exe / xxx.sys 的模块名
      apis      : 导入表/导出表里的函数名（known_apis 精确匹配，否则启发式）
      others    : 其余
    """
    cats = {key: [] for key in _CLASS_KEYS}

    try:
        items = list(strings or ())
    except TypeError:
        items = []

    apis = _as_lower_set(known_apis)
    sections = _as_lower_set(known_sections) or set(_DEFAULT_SECTIONS)

    for raw in items:
        s = raw if isinstance(raw, str) else str(raw)
        norm = _strip_noise(s)
        # URL 检测：strings.exe 扫节区时常带 1 字节字母/数字行首噪音
        # （如 CRL/OCSP 截断里的 `s`、`V`、`3`、`_`、`#`），_strip_noise 不剥字母数字，
        # 这里额外允许从 norm 头部跳过一个字符再匹配；同时保留对原文的全文检索兜底
        # （异常截断位置时仍有 http:// 在字符串中部）。
        tail = norm[1:] if norm else ""
        if _URL_RE.match(norm) or _URL_RE.match(tail) or _URL_RE.search(s):
            cats["urls"].append(s)
        elif "version" not in s.lower() and any(_looks_like_ip(c) for c in _IP_RE.findall(s)):
            cats["ips"].append(s)
        elif _REG_RE.search(s):
            cats["registry"].append(s)
        elif _PATH_RE.search(s):
            cats["paths"].append(s)
        elif _PDB_RE.search(s):
            cats["pdb"].append(s)
        elif _is_xml_line(s):
            cats["xml"].append(s)
        elif norm.lower() in sections:
            cats["sections"].append(s)
        elif _DLL_RE.match(norm):
            cats["dlls"].append(s)
        else:
            # 有真实导入/导出函数名就精确匹配，否则退化到启发式
            is_api = norm.lower() in apis if apis else _looks_like_api(norm)
            cats["apis" if is_api else "others"].append(s)
    return cats


if __name__ == "__main__":
    # 简易自测：从命令行接收一个文件路径并打印提取摘要。
    if len(sys.argv) < 2:
        sys.stderr.write("用法: python strings_extractor.py <文件路径> [最小长度]\n")
        sys.exit(2)

    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    target = sys.argv[1]
    min_len = int(sys.argv[2]) if len(sys.argv) > 2 else 4

    rep = extract_strings(target, min_length=min_len)
    print(f"文件        : {target}")
    print(f"来源        : {rep['source']}")
    print(f"external 条数: {len(rep['external'])}")
    print(f"pefile   条数: {len(rep['pefile'])}")
    print(f"merged   条数: {len(rep['merged'])}")
    print(f"external_ok : {rep['external_ok']}")
    print(f"error        : {rep['error']}")

    print("\nmerged 前 10 条:")
    for line in rep["merged"][:10]:
        print("  " + line)

    cls = classify_strings(rep["merged"])
    print("\n分类命中:")
    for k, v in cls.items():
        print(f"  {k:10s}: {len(v)}")
    sys.exit(0)
