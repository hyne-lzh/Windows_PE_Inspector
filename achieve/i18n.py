"""中英双语支持（Windows PE Inspector）。

本模块只做一件事：把「界面文案」从代码里抽出来，并按当前语言返回。
它不依赖任何 GUI 库，GUI / CLI / 报告导出共用同一套语言键，保证三处文案一致。

设计要点
--------
- 语言包外置在 ``assets/i18n.json``，结构 ``{"zh": {key: text}, "en": {key: text}}``，
  用户可自行修改/新增，无需改代码；
- 内置零文案：文件缺失或损坏时 ``t()`` 直接回退为 key 本身（绝不抛异常、绝不显示空白）；
- 占位符统一用 ``{name}``，通过 ``t("key", n=1)`` 传入；
- 语言状态是本模块的模块级变量，GUI 单线程读写下无需加锁。

对外接口
--------
- set_language(lang) / get_language() -> "zh" | "en"
- t(key, default=None, **fmt) -> str
- available_languages() -> tuple[str, ...]
- missing_keys() -> set[str]   # 便于自检：哪些 key 在当前语言包里找不到
"""

from __future__ import annotations

import json
from pathlib import Path

# 支持的语言（顺序即展示顺序）
LANGUAGES: tuple[str, ...] = ("zh", "en")
DEFAULT_LANGUAGE = "zh"

# 外置语言包路径（项目根 assets/ 下）
I18N_PATH = Path(__file__).resolve().parent.parent / "assets" / "i18n.json"

# 当前语言。默认中文，保持与历史行为一致。
_current_language: str = DEFAULT_LANGUAGE

# 记录找不到的 key（去重），便于开发期自检
_missing_keys: set[str] = set()

# 加载失败的说明（供上层附加到 warnings）
load_error: str | None = None


def _load() -> dict[str, dict[str, str]]:
    """加载语言包。失败时返回空表（t() 会回退为 key），绝不抛异常。"""
    global load_error
    data: dict[str, dict[str, str]] = {lang: {} for lang in LANGUAGES}
    try:
        with I18N_PATH.open(encoding="utf-8") as fh:
            raw = json.load(fh)
    except FileNotFoundError:
        load_error = f"语言包不存在：{I18N_PATH}（界面将显示语言键）"
        return data
    except (OSError, json.JSONDecodeError) as exc:
        load_error = f"语言包读取失败：{exc}（界面将显示语言键）"
        return data

    if not isinstance(raw, dict):
        load_error = "语言包顶层不是对象（应为 {lang: {key: text}}）"
        return data

    for lang in LANGUAGES:
        bucket = raw.get(lang)
        if not isinstance(bucket, dict):
            continue
        for key, value in bucket.items():
            if isinstance(value, str):
                data[lang][str(key)] = value
    return data


STRINGS: dict[str, dict[str, str]] = _load()


def available_languages() -> tuple[str, ...]:
    """返回支持的语言列表。"""
    return LANGUAGES


def set_language(lang: str) -> str:
    """设置当前语言；非法值回退到默认语言。返回实际生效的语言。"""
    global _current_language
    _current_language = lang if lang in LANGUAGES else DEFAULT_LANGUAGE
    return _current_language


def get_language() -> str:
    """返回当前语言。"""
    return _current_language


def missing_keys() -> set[str]:
    """返回截至当前所有查不到（走回退）的 key 集合。"""
    return set(_missing_keys)


def t(key: str, default: str | None = None, lang: str | None = None, **fmt) -> str:
    """取指定语言（默认当前语言）的文案。

    查找顺序：指定/当前语言 → 默认语言(zh) → default → key 本身。
    命中后若传了 ``fmt``，用 ``str.format`` 填充 ``{name}`` 占位符；
    格式化失败（占位符不匹配等）时原样返回，绝不抛异常。
    """
    if not key:
        return default or ""

    use = lang or _current_language
    text = STRINGS.get(use, {}).get(key)
    if text is None and use != DEFAULT_LANGUAGE:
        text = STRINGS.get(DEFAULT_LANGUAGE, {}).get(key)
    if text is None:
        _missing_keys.add(key)
        text = default if default is not None else key

    if fmt:
        try:
            return text.format(**fmt)
        except (KeyError, IndexError, ValueError):
            return text
    return text
