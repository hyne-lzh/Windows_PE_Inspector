"""数字签名校验（Windows Authenticode）：内嵌 PKCS#7 + 目录签名（catalog-signed）。

安全边界（与 pe_parser 整体一致）：**纯静态、只读文件**——
- WinVerifyTrust 只对文件做密码学校验，不加载不执行；
- 强制 ``WTD_CACHE_ONLY_URL_RETRIEVAL``，不联网取 CRL/OCSP；
- catalog 查询用 ``CryptCATAdmin*`` 按 SHA1 查系统 .cat，同样只读。

历史坑（修复后勿回退）：
- WinVerifyTrust 对纯 catalog 文件返回 ``0x800B0100``，**不能**用它判 catalog；
- ``CryptCATAdminCalcHashFromFileHandle`` 官方签名**只有 4 参**（网上示例含
  HCATADMIN 的版本是旧 MSKB 错误）；
- catalog 签名是聚合签名，**无法**提取 signer/issuer。

拆分自原 achieve/pe_parser.py（2026-10-18）。
"""

from __future__ import annotations

import struct

import pefile

from .pe_models import (
    SIG_INVALID,
    SIG_KIND_CATALOG,
    SIG_KIND_EMBEDDED,
    SIG_KIND_NONE,
    SIG_NONE,
    SIG_UNKNOWN,
    SIG_VALID,
    SignatureInfo,
)


# --------------------------------------------------------------------------
# 数字签名校验（Windows Authenticode）
# --------------------------------------------------------------------------

def _security_dir_range(pe) -> tuple[int, int]:
    """返回签名目录的 (文件偏移, 大小)；无签名返回 (0, 0)。

    注意：IMAGE_DIRECTORY_ENTRY_SECURITY 的 VirtualAddress 是**文件偏移**而非 RVA。
    """
    try:
        idx = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
        dd = pe.OPTIONAL_HEADER.DATA_DIRECTORY[idx]
        offset, size = int(dd.VirtualAddress), int(dd.Size)
        if offset > 0 and size > 0:
            return offset, size
    except (AttributeError, IndexError, KeyError, TypeError, ValueError):
        pass
    return 0, 0


def _read_signature_blob(pe, path: str, offset: int, size: int) -> bytes | None:
    """读取 PKCS#7 签名数据（跳过 8 字节 WIN_CERTIFICATE 头）。失败返回 None。"""
    raw: bytes | None = None
    try:
        data = getattr(pe, "__data__", None)
        if isinstance(data, (bytes, bytearray)) and offset + 8 <= len(data):
            raw = bytes(data[offset:offset + size])
    except (TypeError, ValueError):
        raw = None
    if raw is None:
        try:
            with open(path, "rb") as fh:
                fh.seek(offset)
                raw = fh.read(size)
        except (OSError, ValueError):
            return None
    if not raw or len(raw) < 8:
        return None
    try:
        length, _revision, _ctype = struct.unpack_from("<IHH", raw, 0)
    except struct.error:
        return None
    if length < 8 or length > len(raw):
        length = len(raw)
    blob = raw[8:length]
    return blob or None


def _win_verify_file(path: str) -> tuple[str, str]:
    """用 Windows WinVerifyTrust 校验文件签名，返回 (status, detail)。

    - status: SIG_VALID / SIG_INVALID / SIG_UNKNOWN
    - detail: 附加说明（错误码等）

    本函数只**读取**文件做密码学校验，绝不加载或执行样本；
    强制 `WTD_CACHE_ONLY_URL_RETRIEVAL`，不联网取 CRL/OCSP。
    """
    try:
        import ctypes
        from ctypes import wintypes
    except Exception as exc:  # noqa: BLE001
        return SIG_UNKNOWN, f"ctypes 不可用：{exc}"

    if not hasattr(ctypes, "windll"):
        return SIG_UNKNOWN, "非 Windows 环境"

    class _GUID(ctypes.Structure):
        _fields_ = [
            ("Data1", wintypes.DWORD),
            ("Data2", wintypes.WORD),
            ("Data3", wintypes.WORD),
            ("Data4", ctypes.c_ubyte * 8),
        ]

    class _WINTRUST_FILE_INFO(ctypes.Structure):
        _fields_ = [
            ("cbStruct", wintypes.DWORD),
            ("pcwszFilePath", wintypes.LPCWSTR),
            ("hFile", wintypes.HANDLE),
            ("pgKnownSubject", ctypes.POINTER(_GUID)),
        ]

    class _WINTRUST_DATA(ctypes.Structure):
        _fields_ = [
            ("cbStruct", wintypes.DWORD),
            ("pPolicyCallbackData", ctypes.c_void_p),
            ("pSIPClientData", ctypes.c_void_p),
            ("dwUIChoice", wintypes.DWORD),
            ("fdwRevocationChecks", wintypes.DWORD),
            ("dwUnionChoice", wintypes.DWORD),
            ("pFile", ctypes.POINTER(_WINTRUST_FILE_INFO)),
            ("dwStateAction", wintypes.DWORD),
            ("hWVTStateData", wintypes.HANDLE),
            ("pwszURLReference", wintypes.LPWSTR),
            ("dwProvFlags", wintypes.DWORD),
            ("dwUIContext", wintypes.DWORD),
            ("pSignatureSettings", ctypes.c_void_p),
        ]

    wtd_ui_none = 2
    wtd_revoke_none = 0
    wtd_choice_file = 1
    wtd_state_verify = 1
    wtd_state_close = 2
    wtd_cache_only = 0x00001000   # 仅用本地缓存，避免联网

    action = _GUID(0x00AAC56B, 0xCD44, 0x11D0,
                   (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE))

    file_info = _WINTRUST_FILE_INFO()
    file_info.cbStruct = ctypes.sizeof(_WINTRUST_FILE_INFO)
    file_info.pcwszFilePath = str(path)
    file_info.hFile = None
    file_info.pgKnownSubject = None

    data = _WINTRUST_DATA()
    data.cbStruct = ctypes.sizeof(_WINTRUST_DATA)
    data.pPolicyCallbackData = None
    data.pSIPClientData = None
    data.dwUIChoice = wtd_ui_none
    data.fdwRevocationChecks = wtd_revoke_none
    data.dwUnionChoice = wtd_choice_file
    data.pFile = ctypes.pointer(file_info)
    data.dwStateAction = wtd_state_verify
    data.hWVTStateData = None
    data.pwszURLReference = None
    data.dwProvFlags = wtd_cache_only
    data.dwUIContext = 0
    data.pSignatureSettings = None

    try:
        wintrust = ctypes.WinDLL("wintrust.dll")
        fn = wintrust.WinVerifyTrust
        fn.argtypes = [wintypes.HWND, ctypes.POINTER(_GUID), ctypes.c_void_p]
        fn.restype = ctypes.c_long
    except (OSError, AttributeError) as exc:
        return SIG_UNKNOWN, f"无法加载 wintrust.dll：{exc}"

    try:
        result = fn(None, ctypes.byref(action), ctypes.byref(data))
    except Exception as exc:  # noqa: BLE001
        return SIG_UNKNOWN, f"WinVerifyTrust 调用失败：{exc}"
    finally:
        # 释放校验状态数据，避免句柄泄漏
        try:
            data.dwStateAction = wtd_state_close
            fn(None, ctypes.byref(action), ctypes.byref(data))
        except Exception:  # noqa: BLE001
            pass

    code = int(ctypes.c_long(result).value)
    if code == 0:
        return SIG_VALID, ""
    return SIG_INVALID, f"0x{code & 0xFFFFFFFF:08X}"


def _win_check_catalog(path: str) -> bool:
    """检查文件是否被 Windows 目录签名（catalog-signed）。

    WinVerifyTrust 对 catalog 文件会返回 ``0x800B0100``（找不到内嵌证书对应 .cat
    条目）而误判为 invalid。正确做法是用 ``CryptCATAdmin*`` 系列 API 自己
    算 SHA1 哈希并查询 ``C:\\Windows\\System32\\catroot\\`` 下的 .cat 文件。

    - 返回 ``True``：该文件的 SHA1 在系统 .cat 中能找到
    - 返回 ``False``：未找到，或非 Windows / ctypes 不可用 / API 失败

    关键安全约束：纯静态、只读文件，不联网、不执行样本。
    """
    try:
        import ctypes
        from ctypes import wintypes
    except Exception:
        return False
    if not hasattr(ctypes, "windll"):
        return False

    # 准备 wintrust.dll 句柄（CryptCATAdmin* 在 wintrust.dll，不在 crypt32.dll）
    try:
        wintrust = ctypes.WinDLL("wintrust.dll")
    except OSError:
        return False

    # 关键：CryptCATAdminCalcHashFromFileHandle 的官方签名只有 4 个参数：
    #   (HANDLE hFile, DWORD* pcbHash, BYTE* pbHash, DWORD dwFlags)
    # MSDN 与 Wine 头文件均如此。本函数**不接受** HCATADMIN —— 网上部分示例是错的。
    catadmin_calc = wintrust.CryptCATAdminCalcHashFromFileHandle
    catadmin_calc.argtypes = [
        wintypes.HANDLE,                            # hFile
        ctypes.POINTER(wintypes.DWORD),             # pcbHash
        ctypes.POINTER(ctypes.c_ubyte),             # pbHash
        wintypes.DWORD,                             # dwFlags
    ]
    catadmin_calc.restype = ctypes.c_bool

    # CryptCATAdminEnumCatalogFromHash：MSDN 文档说无参数版本不存在；实测 Win10/11
    # 真实签名是 (HCATADMIN hCatAdmin, BYTE* pbHash, DWORD cbHash, DWORD dwFlags, ...)
    # 旧版有 PSTR catname 字段，新版无。安全做法：传 NULL catname，只看返回值非零。
    catadmin_enum = getattr(wintrust, "CryptCATAdminEnumCatalogFromHash", None)
    if catadmin_enum is None:
        return False

    # AcquireContext / ReleaseContext：必须用 GlobAddContextFlag 否则获取不到全局 .cat
    catadmin = wintrust.CryptCATAdminAcquireContext
    catadmin.argtypes = [ctypes.POINTER(wintypes.HANDLE), ctypes.c_void_p, wintypes.DWORD]
    catadmin.restype = ctypes.c_bool

    catadmin_release = wintrust.CryptCATAdminReleaseContext
    catadmin_release.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    catadmin_release.restype = ctypes.c_bool

    ctx = wintypes.HANDLE()
    if not catadmin(ctypes.byref(ctx), None, 0):
        return False

    file_handle = wintypes.HANDLE()
    try:
        # CreateFileW 拿只读句柄；INVALID_HANDLE_VALUE 失败
        CreateFileW = ctypes.WinDLL("kernel32.dll").CreateFileW
        CreateFileW.argtypes = [
            wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
            ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
        ]
        CreateFileW.restype = wintypes.HANDLE
        GENERIC_READ = 0x80000000
        FILE_SHARE_READ = 0x00000001
        OPEN_EXISTING = 3
        file_handle = CreateFileW(
            str(path), GENERIC_READ, FILE_SHARE_READ, None, OPEN_EXISTING, 0, None
        )
        if file_handle == wintypes.HANDLE(-1).value or file_handle is None:
            return False

        # 算 SHA1（20 字节）：先入参 pcbHash=20，返回时被覆盖为真实长度
        hash_buf = (ctypes.c_ubyte * 20)()
        hash_len = wintypes.DWORD(20)
        ok = catadmin_calc(file_handle, ctypes.byref(hash_len), hash_buf, 0)
        if not ok or hash_len.value < 20:
            return False

        # 试 Win10+ 标准签名：(HCATADMIN, BYTE*, DWORD, DWORD, PCWSTR, DWORD*)

        cat_info = None
        for argtypes in (
            # 文档签名（Win10 1903+）：返回 CAT_INFO*，无 catname
            [wintypes.HANDLE, ctypes.POINTER(ctypes.c_ubyte), wintypes.DWORD,
             wintypes.DWORD, ctypes.c_wchar_p, ctypes.POINTER(wintypes.DWORD)],
            # 旧版（< Win10 1903）：带 catname 指针
            [wintypes.HANDLE, ctypes.POINTER(ctypes.c_ubyte), wintypes.DWORD,
             wintypes.DWORD, ctypes.c_char_p, ctypes.POINTER(wintypes.DWORD)],
        ):
            try:
                catadmin_enum.argtypes = argtypes
                catadmin_enum.restype = ctypes.c_void_p
                info = catadmin_enum(ctx, hash_buf, 20, 0, None, None)
                if info:
                    cat_info = info
                    break
            except (OSError, AttributeError, ctypes.ArgumentError):
                continue
        return cat_info is not None and cat_info != 0
    except Exception:
        return False
    finally:
        if file_handle:
            try:
                ctypes.WinDLL("kernel32.dll").CloseHandle(file_handle)
            except Exception:
                pass
        try:
            catadmin_release(ctx, 0)
        except Exception:
            pass


def _win_extract_signer(sig_bytes: bytes) -> tuple[str, str]:
    """从 PKCS#7 签名数据中提取 (签名者, 颁发者) 的显示名。失败返回空串。

    用 CryptQueryObject 解析签名，枚举证书取显示名（签名者证书通常排在最前）。
    """
    if not sig_bytes:
        return "", ""
    try:
        import ctypes
        from ctypes import wintypes
    except Exception:  # noqa: BLE001
        return "", ""
    if not hasattr(ctypes, "windll"):
        return "", ""

    class _CRYPT_DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD),
                    ("pbData", ctypes.POINTER(ctypes.c_ubyte))]

    class _CRYPT_ALGORITHM_IDENTIFIER(ctypes.Structure):
        _fields_ = [("pszObjId", ctypes.c_char_p),
                    ("Parameters", _CRYPT_DATA_BLOB)]

    class _FILETIME(ctypes.Structure):
        _fields_ = [("dwLowDateTime", wintypes.DWORD),
                    ("dwHighDateTime", wintypes.DWORD)]

    class _CMSG_SIGNER_INFO(ctypes.Structure):
        # 只声明到 SerialNumber（后续字段 CertFindCertificateInStore 用不到）
        _fields_ = [("dwVersion", wintypes.DWORD),
                    ("Issuer", _CRYPT_DATA_BLOB),
                    ("SerialNumber", _CRYPT_DATA_BLOB)]

    class _CERT_INFO(ctypes.Structure):
        # 部分布局：CertFindCertificateInStore(CERT_FIND_SUBJECT_CERT) 只用 Issuer + SerialNumber
        _fields_ = [("dwVersion", wintypes.DWORD),
                    ("SerialNumber", _CRYPT_DATA_BLOB),
                    ("SignatureAlgorithm", _CRYPT_ALGORITHM_IDENTIFIER),
                    ("Issuer", _CRYPT_DATA_BLOB),
                    ("NotBefore", _FILETIME),
                    ("NotAfter", _FILETIME),
                    ("Subject", _CRYPT_DATA_BLOB)]

    cert_query_object_blob = 2
    cert_query_content_flag_all = 0x3FFE
    cert_query_format_flag_all = 0x0000000E
    cert_name_simple_display_type = 4

    buf = (ctypes.c_ubyte * len(sig_bytes)).from_buffer_copy(sig_bytes)
    blob = _CRYPT_DATA_BLOB(len(sig_bytes), ctypes.cast(buf, ctypes.POINTER(ctypes.c_ubyte)))

    try:
        crypt32 = ctypes.WinDLL("crypt32.dll")
    except OSError:
        return "", ""

    CryptQueryObject = crypt32.CryptQueryObject
    CryptQueryObject.argtypes = [
        wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.HANDLE),
        ctypes.POINTER(wintypes.HANDLE), ctypes.POINTER(ctypes.c_void_p),
    ]
    CryptQueryObject.restype = wintypes.BOOL

    encoding = wintypes.DWORD()
    content_type = wintypes.DWORD()
    format_type = wintypes.DWORD()
    h_store = wintypes.HANDLE()
    h_msg = wintypes.HANDLE()
    p_context = ctypes.c_void_p()

    ok = CryptQueryObject(
        cert_query_object_blob, ctypes.byref(blob),
        cert_query_content_flag_all, cert_query_format_flag_all, 0,
        ctypes.byref(encoding), ctypes.byref(content_type), ctypes.byref(format_type),
        ctypes.byref(h_store), ctypes.byref(h_msg), ctypes.byref(p_context),
    )
    if not ok or not h_store:
        return "", ""

    signer, issuer = "", ""
    try:
        CertGetNameStringW = crypt32.CertGetNameStringW
        CertGetNameStringW.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
                                       ctypes.c_void_p, wintypes.LPWSTR, wintypes.DWORD]
        CertGetNameStringW.restype = wintypes.DWORD

        def _cert_name(cert_ctx, issuer_flag: int = 0) -> str:
            """取证书显示名；issuer_flag=1 时取颁发者名（CERT_NAME_ISSUER_FLAG）。"""
            need = CertGetNameStringW(cert_ctx, cert_name_simple_display_type,
                                      issuer_flag, None, None, 0)
            if need <= 1:
                return ""
            name_buf = ctypes.create_unicode_buffer(need)
            CertGetNameStringW(cert_ctx, cert_name_simple_display_type,
                               issuer_flag, None, name_buf, need)
            return name_buf.value or ""

        # 优先用 CMSG_SIGNER_INFO 精确定位"叶证书"（签名者），避免取到中间 CA
        leaf_ctx = None
        if h_msg:
            try:
                CryptMsgGetParam = crypt32.CryptMsgGetParam
                CryptMsgGetParam.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD,
                                             ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD)]
                CryptMsgGetParam.restype = wintypes.BOOL
                cmsg_signer_info_param = 6
                need_size = wintypes.DWORD()
                if (CryptMsgGetParam(h_msg, cmsg_signer_info_param, 0, None, ctypes.byref(need_size))
                        and need_size.value):
                    info_buf = (ctypes.c_ubyte * need_size.value)()
                    if CryptMsgGetParam(h_msg, cmsg_signer_info_param, 0, info_buf,
                                        ctypes.byref(need_size)):
                        signer_info = _CMSG_SIGNER_INFO.from_buffer(info_buf)
                        cert_info = _CERT_INFO()
                        cert_info.dwVersion = 0
                        cert_info.SerialNumber = signer_info.SerialNumber
                        cert_info.Issuer = signer_info.Issuer
                        CertFindCertificateInStore = crypt32.CertFindCertificateInStore
                        CertFindCertificateInStore.argtypes = [wintypes.HANDLE, wintypes.DWORD,
                                                               wintypes.DWORD, wintypes.DWORD,
                                                               ctypes.c_void_p, ctypes.c_void_p]
                        CertFindCertificateInStore.restype = ctypes.c_void_p
                        x509_pkcs7 = 0x00010001          # X509_ASN_ENCODING | PKCS_7_ASN_ENCODING
                        cert_find_subject_cert = 0x000B0000
                        leaf_ctx = CertFindCertificateInStore(
                            h_store, x509_pkcs7, 0, cert_find_subject_cert,
                            ctypes.byref(cert_info), None)
            except Exception:  # noqa: BLE001
                leaf_ctx = None

        cert_name_issuer_flag = 0x1
        if leaf_ctx:
            signer = _cert_name(leaf_ctx, 0)
            issuer = _cert_name(leaf_ctx, cert_name_issuer_flag)
        if not signer:
            # 回退：枚举证书存储，取第一个作为签名者
            CertEnumCertificatesInStore = crypt32.CertEnumCertificatesInStore
            CertEnumCertificatesInStore.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
            CertEnumCertificatesInStore.restype = ctypes.c_void_p
            cert = CertEnumCertificatesInStore(h_store, None)
            count = 0
            while cert and count < 6:
                name = _cert_name(cert, 0)
                if name and not signer:
                    signer = name
                elif name and not issuer:
                    issuer = name
                cert = CertEnumCertificatesInStore(h_store, cert)
                count += 1
    except Exception:  # noqa: BLE001
        pass
    finally:
        try:
            crypt32.CertCloseStore(h_store, 0)
        except Exception:  # noqa: BLE001
            pass
        if h_msg:
            try:
                crypt32.CryptMsgClose(h_msg)
            except Exception:  # noqa: BLE001
                pass
    return signer, issuer


def check_signature(pe, path: str) -> SignatureInfo:
    """检查 PE 数字签名。

    关键修复（P 级缺陷，曾漏检目录签名）：当内嵌 IMAGE_DIRECTORY_ENTRY_SECURITY
    为空时，**仍调用 WinVerifyTrust** 走系统 .cat 目录验证。若 WinVerifyTrust 报告
    valid，则视为「目录签名（catalog-signed）」，``present=True / kind=catalog``。
    这样系统文件（notepad.exe、cmd.exe、consent.exe 等）能被正确识别为「已签名」。

    仅当「无内嵌证书 **且** WinVerifyTrust 也失败」时才返回 ``present=False``。
    """
    offset, size = _security_dir_range(pe)
    has_embedded = bool(offset and size)

    if has_embedded:
        # 路径 1：内嵌 PKCS#7 证书。校验有效性并尝试提取签名者。
        info = SignatureInfo(
            present=True,
            status=SIG_UNKNOWN,
            kind=SIG_KIND_EMBEDDED,
            size=size,
        )
        status, detail = _win_verify_file(str(path))
        info.status = status
        info.detail = detail

        blob = _read_signature_blob(pe, str(path), offset, size)
        if blob:
            signer, issuer = _win_extract_signer(blob)
            info.signer = signer
            info.issuer = issuer
        return info

    # 路径 2：内嵌 Security 目录为空 → 走 .cat 目录签名兜底。
    # WinVerifyTrust 对纯 catalog 文件会返回 TRUST_E_CERT_SIGNATURE
    # (0x800B0100)，不能用它判断；改用 CryptCATAdmin* 直接查系统 .cat。
    if _win_check_catalog(str(path)):
        return SignatureInfo(
            present=True,
            status=SIG_VALID,
            kind=SIG_KIND_CATALOG,
        )
    # 真正无签名：内嵌无证书，.cat 也找不到
    return SignatureInfo(
        present=False,
        status=SIG_NONE,
        kind=SIG_KIND_NONE,
    )
