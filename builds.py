"""PE Inspector 一键编译脚本（Nuitka / standalone 模式）。

默认就是**全自动**：环境预检 → 编译器缓存检查 → 网络与加速器诊断 → 实测下载速度
→ 自动挑选编译器后端 → 编译。中途不需要任何交互。

用法：
    python builds.py                    # 全自动（推荐）
    python builds.py --backend mingw64  # 强制用 MinGW64
    python builds.py --backend zig      # 强制用 Zig（绕开 GitHub）
    python builds.py --min-speed 1.5    # 改自动切换阈值（默认 1.0 MB/s）
    python builds.py --test-net         # 只做网络诊断 + 测速
    python builds.py --check-env        # 只看环境、缓存与网络状态
    python builds.py --dry-run          # 只打印编译命令，不真编译
    python builds.py --clean            # 删除编译产物

自动化决策规则（--backend auto，即默认）：
    1) 本地已缓存 MinGW64        → 直接用 MinGW64（零下载）
    2) 否则已缓存 Zig            → 直接用 Zig（零下载）
    3) 都没有缓存                → 先测速：
         · GitHub 实测 ≥ --min-speed → MinGW64
         · 低于阈值或测速失败        → 再测 PyPI，确认可行后用 Zig

设计说明：
- 只依赖标准库，不引入任何第三方包。
- 本脚本自身**不参与编译**，所以不受 --python-flag=no_site 影响。
- 编译模式固定 --standalone，本项目不使用 --onefile。
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

# 中文输出在 GBK 控制台下容易报 UnicodeEncodeError，统一切到 UTF-8。
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8", errors="replace")

ROOT = Path(__file__).resolve().parent
ENTRY = ROOT / "main.py"
OUTPUT_NAME = "PEInspector.exe"
DIST_DIR = ROOT / "main.dist"

PY_MIN = (3, 12)
PY_MAX_EXCLUSIVE = (3, 13)

# Nuitka 下载的 winlibs 版本（目录名含版本号，升级 Nuitka 后可能变化）
WINLIBS_VERSION = "15.2.0posix-13.0.0-msvcrt-r6"
WINLIBS_ZIP_NAME = "winlibs-x86_64-posix-seh-gcc-15.2.0-mingw-w64msvcrt-13.0.0-r6.zip"
WINLIBS_URL = (
    "https://github.com/brechtsanders/winlibs_mingw/releases/download/"
    f"{WINLIBS_VERSION}/{WINLIBS_ZIP_NAME}"
)
WINLIBS_SIZE_MB = 255
ZIG_SIZE_MB = 94  # ziglang wheel 实测体积（PyPI）

PYPI_ZIGLANG_JSON = "https://pypi.org/pypi/ziglang/json"

DEFAULT_MIN_SPEED = 1.0  # MB/s，低于此值自动改用 Zig

# 视为"加速器接管"的回环地址
LOOPBACK = {"127.0.0.1", "::1", "0.0.0.0", "localhost"}

# 与 md/nuitka_install.md 中记录的命令保持一致
COMMON_ARGS = [
    "--standalone",
    "--enable-plugin=tk-inter",
    "--windows-console-mode=disable",
    "--lto=yes",
    "--python-flag=no_asserts",
    "--python-flag=no_docstrings",
    "--python-flag=no_site",
    "--python-flag=no_warnings",
    "--noinclude-setuptools-mode=nofollow",
    f"--output-filename={OUTPUT_NAME}",
]

BACKEND_ARGS = {
    "mingw64": ["--mingw64"],
    "zig": ["--zig"],
}

BACKEND_DESC = {
    "mingw64": f"MinGW64（GitHub 下载，约 {WINLIBS_SIZE_MB} MB）",
    "zig": f"Zig（PyPI 下载，约 {ZIG_SIZE_MB} MB，不经 GitHub）",
}


# --------------------------------------------------------------------------
# 输出小工具
# --------------------------------------------------------------------------

def log(msg: str = "") -> None:
    print(msg, flush=True)


def rule(title: str) -> None:
    log("")
    log(f"== {title} ==")


# --------------------------------------------------------------------------
# 环境检查
# --------------------------------------------------------------------------

def check_python() -> bool:
    v = sys.version_info
    log(f"Python     : {v.major}.{v.minor}.{v.micro}  ({sys.executable})")
    if (v.major, v.minor) >= PY_MAX_EXCLUSIVE:
        log("  [x] 3.13+ 不被 MinGW64 后端支持，请改用 3.12.x")
        return False
    if (v.major, v.minor) < PY_MIN:
        log("  [x] 版本过低，需要 3.12.x")
        return False
    log("  [ok] 版本符合要求（3.12.x，避开 3.13+ 的 MinGW64 限制）")
    return True


def check_nuitka() -> bool:
    try:
        out = subprocess.run(
            [sys.executable, "-m", "nuitka", "--version"],
            capture_output=True,
            text=True,
            timeout=90,
        )
    except Exception as exc:  # noqa: BLE001
        log(f"  [x] 无法调用 Nuitka：{exc}")
        return False

    if out.returncode != 0:
        log("  [x] 未安装 Nuitka，请先执行：pip install nuitka")
        return False

    # nuitka --version 的第一行就是纯版本号，例如 "4.2.1"
    version = ""
    for line in (out.stdout or "").splitlines():
        line = line.strip()
        if line:
            version = line
            break
    log(f"Nuitka     : {version or '已安装'}")
    return True


# --------------------------------------------------------------------------
# 编译器缓存
# --------------------------------------------------------------------------

def nuitka_download_cache() -> Path:
    """Nuitka 的下载缓存根目录（Windows）。"""
    local = os.environ.get("LOCALAPPDATA", "")
    return Path(local) / "Nuitka" / "Nuitka" / "Cache" / "downloads"


def mingw_zip_path() -> Path:
    return nuitka_download_cache() / "gcc" / "x86_64" / WINLIBS_VERSION / WINLIBS_ZIP_NAME


def scan_backend_cache() -> dict[str, bool]:
    """检查两个后端的编译器是否已就位（就位 = 编译时零下载）。"""
    zip_path = mingw_zip_path()
    extracted = zip_path.parent / "mingw64" / "bin" / "gcc.exe"
    mingw_ok = extracted.is_file() or zip_path.is_file()

    zig_ok = False
    pip_space = nuitka_download_cache() / "pip"
    if pip_space.is_dir():
        zig_ok = any(pip_space.glob("private-*/Lib/site-packages/ziglang/zig.exe"))

    return {"mingw64": mingw_ok, "zig": zig_ok}


def report_backend_cache(cached: dict[str, bool]) -> None:
    zip_path = mingw_zip_path()
    if cached["mingw64"]:
        if (zip_path.parent / "mingw64" / "bin" / "gcc.exe").is_file():
            log("MinGW64    : [ok] 已解压可用（编译时零下载）")
        else:
            size = zip_path.stat().st_size / 1024 / 1024
            log(f"MinGW64    : [ok] 已缓存安装包 {size:.0f} MB（编译时零下载）")
    else:
        log(f"MinGW64    : [ ] 未缓存，使用需下载约 {WINLIBS_SIZE_MB} MB")
        log(f"             缓存路径：{zip_path}")

    if cached["zig"]:
        log(f"Zig        : [ok] 已就位（编译时零下载）")
    else:
        log(f"Zig        : [ ] 未缓存，使用需下载约 {ZIG_SIZE_MB} MB")


# --------------------------------------------------------------------------
# 网络与加速器诊断
# --------------------------------------------------------------------------

def hosts_file() -> Path:
    root = os.environ.get("SystemRoot") or r"C:\Windows"
    return Path(root) / "System32" / "drivers" / "etc" / "hosts"


def scan_hosts_redirects() -> list[tuple[str, str]]:
    """找出 hosts 中把 GitHub 相关域名指向回环地址的条目。

    Steam++ / Watt Toolkit 这类"加速器"的典型做法就是把 github.com 等域名
    指向 127.0.0.1，交由本机反代接管。一旦加速器没在运行，GitHub 会**直接
    不可达**（连接被立即拒绝，而不是慢），测速结果也就没有参考价值。
    """
    found: list[tuple[str, str]] = []
    try:
        text = hosts_file().read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return found

    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        ip, names = parts[0], parts[1:]
        if ip not in LOOPBACK:
            continue
        for name in names:
            n = name.lower().rstrip(".")
            if "github" in n:
                found.append((n, ip))
    return found


def detect_proxy_env() -> list[str]:
    hits = []
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
                "http_proxy", "https_proxy", "all_proxy"):
        val = os.environ.get(key)
        if val:
            hits.append(f"{key}={val}")
    return hits


def detect_system_proxy() -> str | None:
    if os.name != "nt":
        return None
    try:
        import winreg  # noqa: PLC0415
    except ImportError:
        return None
    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        ) as key:
            enabled, _ = winreg.QueryValueEx(key, "ProxyEnable")
            if not enabled:
                return None
            server, _ = winreg.QueryValueEx(key, "ProxyServer")
            return str(server) if server else None
    except OSError:
        return None


def resolve_host(name: str) -> str | None:
    try:
        infos = socket.getaddrinfo(name, 443, proto=socket.IPPROTO_TCP)
    except OSError:
        return None
    for info in infos:
        ip = info[4][0]
        if ip:
            return ip
    return None


def diagnose_network() -> dict:
    """打印代理 / hosts / DNS 状态，返回诊断结果。

    这一步的目的就是**防止加速器干扰判断**：先把当前链路的真实形态摆出来，
    再测速，才不会出现"测速通过、编译却下载失败"这种事。
    """
    result = {"accelerator": False, "proxy": []}

    hits = scan_hosts_redirects()
    if hits:
        result["accelerator"] = True
        log(f"  [!] hosts 中 {len(hits)} 条 GitHub 域名被指向回环地址：")
        for name, ip in hits[:6]:
            log(f"        {ip:<12} {name}")
        if len(hits) > 6:
            log(f"        ...（其余 {len(hits) - 6} 条略）")
        log("  [!] 这是 Steam++ / Watt Toolkit 一类加速器的特征：")
        log("      - 只有加速器【正在运行】时 GitHub 才连通；")
        log("      - 测速前请确认加速器已启动，编译全程【不要中途开关它】；")
        log("      - 若不想依赖加速器，见 md/nuitka_install.md「路线一」注释掉该段。")
    else:
        log("  [ok] hosts 未发现 GitHub 域名被指向回环地址")

    proxies = detect_proxy_env()
    sysproxy = detect_system_proxy()
    if proxies:
        log("  [!] 检测到代理环境变量：" + "、".join(proxies))
    if sysproxy:
        log(f"  [!] 检测到系统代理：{sysproxy}")
    if not proxies and not sysproxy:
        log("  [ok] 未检测到代理设置（走直连）")
    result["proxy"] = proxies + ([f"系统代理 {sysproxy}"] if sysproxy else [])

    ip = resolve_host("github.com")
    if ip is None:
        log("  [!] github.com DNS 解析失败（测速多半也会失败）")
    elif ip in LOOPBACK:
        result["accelerator"] = True
        log(f"  [!] github.com 解析到 {ip}（本机回环）—— 已确认由加速器接管")
    else:
        log(f"  [i] github.com 当前解析到 {ip}")

    return result


# --------------------------------------------------------------------------
# 下载测速
# --------------------------------------------------------------------------

def probe_download(
    url: str,
    limit_mb: int,
    time_limit: float,
    use_proxy: bool,
) -> tuple[float | None, str]:
    """对 url 发起 Range 请求实测吞吐，返回 (速度MB/s 或 None, 说明文字)。"""
    limit = limit_mb * 1024 * 1024
    if use_proxy:
        opener = urllib.request.build_opener()
        tag = "经系统/环境代理"
    else:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        tag = "直连（忽略代理）"

    req = urllib.request.Request(
        url,
        headers={
            "Range": f"bytes=0-{limit - 1}",
            "User-Agent": "Mozilla/5.0 (PE-Inspector build check)",
        },
    )

    started = time.monotonic()
    received = 0
    status = None
    try:
        with opener.open(req, timeout=15) as resp:
            status = getattr(resp, "status", None)
            while True:
                if time.monotonic() - started >= time_limit:
                    break
                chunk = resp.read(64 * 1024)
                if not chunk:
                    break
                received += len(chunk)
                if received >= limit:
                    break
    except urllib.error.HTTPError as exc:
        return None, f"{tag}：HTTP {exc.code} {exc.reason}"
    except Exception as exc:  # noqa: BLE001
        return None, f"{tag}：{type(exc).__name__}: {exc}"

    elapsed = max(time.monotonic() - started, 0.001)
    mb = received / 1024 / 1024
    if mb <= 0:
        return None, f"{tag}：未收到数据"
    speed = mb / elapsed
    return speed, f"{tag}：{mb:.1f} MB / {elapsed:.1f} 秒 = {speed:.2f} MB/s（HTTP {status}）"


def show_github_speed(limit_mb: int = 5, time_limit: float = 15.0) -> float | None:
    """实测 GitHub 上下载 MinGW64 的速度。不用 ping，理由见下方说明。"""
    log(f"目标文件   : winlibs MinGW64 安装包（完整约 {WINLIBS_SIZE_MB} MB）")
    log(f"测速方式   : 对该文件发起 HTTP Range 请求，最多取 {limit_mb} MB / 最多 {time_limit:.0f} 秒")
    log("不用 ping ：ICMP 与 HTTP 下载走的服务器/CDN 节点不同，GitHub 又常丢弃 ICMP，")
    log("             ping 通不代表下得动，ping 值（毫秒）也换算不出下载时长。")
    log("")

    speed, note = probe_download(WINLIBS_URL, limit_mb, time_limit, use_proxy=True)
    log(f"  [1] {note}")

    proxy_hint = detect_proxy_env() or detect_system_proxy()
    if speed is None and proxy_hint:
        log("  [!] 检测到代理/加速器，再走一次直连以排除其干扰 ……")
        speed2, note2 = probe_download(WINLIBS_URL, limit_mb, time_limit, use_proxy=False)
        log(f"  [2] {note2}")
        if speed2 is not None:
            log("")
            log("  [i] 直连可以下载 —— 说明瓶颈出在加速器/代理本身，而不是你的网络。")
            log("      处理方式：关掉加速器再编译，或按「路线二」换 Zig 后端。")
            return speed2
        return None

    if speed is None:
        log("")
        log("  [结论] GitHub 下载失败。")
        return None

    log("")
    if speed > 0:
        log(f"  完整 {WINLIBS_SIZE_MB} MB 安装包预计约 {WINLIBS_SIZE_MB / speed / 60:.0f} 分钟。")
    return speed


def show_pypi_speed(limit_mb: int = 3, time_limit: float = 12.0) -> tuple[float | None, str]:
    """实测 PyPI 上 ziglang wheel 的下载速度（判断 Zig 路线是否可行）。"""
    log("查询 PyPI 上 ziglang 的 Windows wheel ……")
    try:
        with urllib.request.urlopen(PYPI_ZIGLANG_JSON, timeout=15) as resp:
            data = json.load(resp)
    except Exception as exc:  # noqa: BLE001
        return None, f"PyPI 元数据请求失败：{type(exc).__name__}: {exc}"

    url = None
    size_mb = 0.0
    for item in data.get("urls", []):
        name = item.get("filename", "")
        if "win" in name and ("amd64" in name or "x86_64" in name):
            url = item.get("url")
            size_mb = item.get("size", 0) / 1024 / 1024
            break
    if not url:
        return None, "未在 PyPI 上找到 Windows 版 wheel"

    speed, note = probe_download(url, limit_mb, time_limit, use_proxy=True)
    detail = note.split("：", 1)[-1]
    if speed is None:
        return None, f"PyPI ziglang wheel（{size_mb:.0f} MB）：{detail}"
    return speed, f"PyPI ziglang wheel（{size_mb:.0f} MB）：{detail}"


def advise_network() -> None:
    log("")
    log("可尝试（详见 md/nuitka_install.md）：")
    log("  1) 启动加速器后重跑本脚本（若 hosts 里 GitHub 指向 127.0.0.1）")
    log("  2) 挂 GitHub520 hosts 并 ipconfig /flushdns，再重跑 --test-net")
    log("  3) 换后端：python builds.py --backend zig")


# --------------------------------------------------------------------------
# 编译
# --------------------------------------------------------------------------

def build(backend: str, jobs: int | None, dry_run: bool) -> int:
    if not ENTRY.is_file():
        log(f"[x] 找不到入口文件：{ENTRY}")
        log("    请先创建 main.py，再执行编译。")
        return 2

    cmd = [sys.executable, "-m", "nuitka"]
    cmd += BACKEND_ARGS[backend]
    cmd += ["--assume-yes-for-downloads"]
    if jobs:
        cmd.append(f"--jobs={jobs}")
    cmd += COMMON_ARGS
    cmd.append(ENTRY.name)

    log(f"后端       : {BACKEND_DESC[backend]}")
    log("命令       :")
    log(" ".join(cmd))
    log("")

    if dry_run:
        log("[dry-run] 未真正执行。")
        return 0

    started = time.monotonic()
    code = subprocess.call(cmd, cwd=str(ROOT))
    elapsed = time.monotonic() - started

    log("")
    if code != 0:
        log(f"[x] 编译失败（退出码 {code}），耗时 {elapsed:.0f} 秒。")
        log("    排查见 md/nuitka_install.md「常见问题排查」：")
        log("    - 报错看不到：把 --windows-console-mode 改成 attach 再跑一次")
        log("    - 缺模块：用 --include-module=xxx 补，分批补")
        log("    - 卡在下载：先 python builds.py --test-net 看链路，再换 --backend zig")
        return code

    log(f"[ok] 编译完成，耗时 {elapsed:.0f} 秒。")
    log(f"     产物目录：{DIST_DIR}")
    exe = DIST_DIR / OUTPUT_NAME
    log(f"     可执行文件：{exe if exe.is_file() else '(请检查 --output-filename)'}")
    if DIST_DIR.is_dir():
        total = sum(f.stat().st_size for f in DIST_DIR.rglob("*") if f.is_file())
        log(f"     目录体积：{total / 1024 / 1024:.1f} MB")
    log("     分发方式：把整个 main.dist 文件夹压成 zip 拷给别人即可运行。")
    return 0


def clean() -> int:
    removed = []
    for target in (DIST_DIR, ROOT / "main.build", ROOT / "main.onefile-build"):
        if target.exists():
            shutil.rmtree(target, ignore_errors=True)
            removed.append(target.name)
    if removed:
        log("[ok] 已删除：" + "、".join(removed))
    else:
        log("没有需要清理的产物。")
    return 0


def choose_backend(
    requested: str,
    cached: dict[str, bool],
    min_speed: float,
) -> str:
    """决定用哪个后端。requested 为 "auto" 时走自动决策。"""
    if requested != "auto":
        log(f"→ 使用命令行指定的后端：{requested}")
        if not cached[requested]:
            log(f"  [i] 该后端尚未缓存，编译时会联网下载（{BACKEND_DESC[requested]}）")
            log("  [i] 编译期间请保持网络与加速器状态稳定，不要中途开关。")
        return requested

    if cached["mingw64"]:
        log("→ 选定后端：mingw64（本地已缓存，零下载，无需测速）")
        return "mingw64"
    if cached["zig"]:
        log("→ 选定后端：zig（本地已缓存，零下载，无需测速）")
        return "zig"

    log("两个后端都未缓存，需要联网下载编译器，先测速再决定。")
    log("")
    speed = show_github_speed()
    log("")

    if speed is not None and speed >= min_speed:
        log(f"→ 选定后端：mingw64（GitHub 实测 {speed:.2f} MB/s ≥ 阈值 {min_speed:g} MB/s）")
        return "mingw64"

    if speed is None:
        log(f"GitHub 链路不可用 → 检查备选链路（Zig / PyPI）")
    else:
        eta = WINLIBS_SIZE_MB / speed / 60 if speed > 0 else float("inf")
        log(f"GitHub 实测 {speed:.2f} MB/s < 阈值 {min_speed:g} MB/s"
            f"（下载 255 MB 约 {eta:.0f} 分钟）→ 检查备选链路（Zig / PyPI）")
    log("")

    pypi_speed, note = show_pypi_speed()
    log(f"  {note}")

    if pypi_speed is None:
        log("")
        log("[x] GitHub 与 PyPI 链路都不通，无法自动下载编译器。")
        advise_network()
        log("")
        log("仍将按 zig 后端尝试编译（若网络恢复即可成功）。")
        return "zig"

    log("")
    log(f"→ 选定后端：zig（PyPI 实测 {pypi_speed:.2f} MB/s，且不经 GitHub）")
    return "zig"


# --------------------------------------------------------------------------
# 入口
# --------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Windows PE Inspector 编译脚本（Nuitka / standalone，默认全自动）",
    )
    parser.add_argument(
        "--backend",
        choices=["auto", *sorted(BACKEND_ARGS)],
        default="auto",
        help="C 编译器后端：auto（默认，自动测速择优）/ mingw64 / zig",
    )
    parser.add_argument("--jobs", type=int, default=None, help="并行编译进程数，如 --jobs=4")
    parser.add_argument(
        "--min-speed",
        type=float,
        default=DEFAULT_MIN_SPEED,
        help=f"自动模式下的速度阈值（MB/s），低于则改用 Zig（默认 {DEFAULT_MIN_SPEED:g}）",
    )
    parser.add_argument("--test-net", action="store_true", help="只做网络诊断 + 测速（不用 ping）")
    parser.add_argument("--check-env", action="store_true", help="检查环境、编译器缓存与网络状态")
    parser.add_argument("--dry-run", action="store_true", help="只打印命令，不真正编译")
    parser.add_argument("--clean", action="store_true", help="删除 main.dist / main.build 等产物")
    args = parser.parse_args()

    if args.clean:
        return clean()

    if args.check_env:
        rule("环境检查")
        ok = check_python()
        log("")
        ok = check_nuitka() and ok
        rule("编译器缓存")
        report_backend_cache(scan_backend_cache())
        rule("网络与代理诊断")
        diagnose_network()
        return 0 if ok else 1

    if args.test_net:
        rule("网络与代理诊断")
        diagnose_network()
        rule("GitHub 下载测速")
        speed = show_github_speed()
        if speed is None or speed < args.min_speed:
            rule("备选链路测速（PyPI / Zig）")
            _, note = show_pypi_speed()
            log(f"  {note}")
            log("")
            advise_network()
        return 0

    rule("1/5 环境检查")
    if not check_python():
        return 1
    log("")
    if not check_nuitka():
        return 1
    if not ENTRY.is_file():
        log("")
        log(f"[x] 找不到入口文件：{ENTRY}")
        log("    请先创建 main.py，再执行编译。")
        return 2

    rule("2/5 编译器缓存")
    cached = scan_backend_cache()
    report_backend_cache(cached)

    rule("3/5 网络与代理诊断")
    diagnose_network()

    rule("4/5 选择编译器后端")
    backend = choose_backend(args.backend, cached, args.min_speed)

    rule("5/5 编译")
    return build(backend, args.jobs, args.dry_run)


if __name__ == "__main__":
    sys.exit(main())
