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
- classify_strings(strings) -> dict
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


def classify_strings(strings: list[str]) -> dict:
    """把字符串按可疑类型分类，返回各类命中列表。

    分类优先级（每个字符串仅归入首个匹配类别）：
      urls      : 以 http:// / https:// / ftp:// 开头
      ips       : IPv4 点分十进制
      registry  : 含 HKEY_ 或 HKLM\\ / HKCU\\ / Software\\ 等注册表特征
      paths     : Windows 路径（C:\\...）或 UNC（\\\\...）
      pdb       : 含 .pdb（PDB 调试符号路径，常泄露编译机目录）
      others    : 其余
    """
    cats = {
        "urls": [],
        "ips": [],
        "registry": [],
        "paths": [],
        "pdb": [],
        "others": [],
    }
    for s in strings:
        if _URL_RE.search(s):
            cats["urls"].append(s)
        elif "version" not in s.lower() and any(_looks_like_ip(c) for c in _IP_RE.findall(s)):
            cats["ips"].append(s)
        elif _REG_RE.search(s):
            cats["registry"].append(s)
        elif _PATH_RE.search(s):
            cats["paths"].append(s)
        elif _PDB_RE.search(s):
            cats["pdb"].append(s)
        else:
            cats["others"].append(s)
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
