# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright 2026 Syranyne

"""Identity equality for independent review.

identity_key folds case, width, format characters, combining marks and
cross-script homoglyphs, so that two identifiers which render alike compare
equal. Homoglyphs use the full Unicode confusables table (UTS #39 skeleton,
see _confusables_data.py), plus a small hand table kept as a fallback.
"""
import unicodedata

from three_inequality_nets.nets.composition._confusables_data import CONFUSABLES as _UNICODE_CONFUSABLES

# 补充同形字（小写，casefold 之后）→ 拉丁字母。完整映射在 _UNICODE_CONFUSABLES。
_CONFUSABLES = {
    # Cyrillic
    "а": "a", "в": "b", "е": "e", "ё": "e", "к": "k", "м": "m", "н": "h", "о": "o",
    "р": "p", "с": "c", "т": "t", "у": "y", "х": "x", "ѕ": "s", "і": "i", "ї": "i",
    "ј": "j", "һ": "h", "ԁ": "d", "ԛ": "q", "ԝ": "w", "ӏ": "l", "ɡ": "g", "ь": "b",
    "п": "n", "г": "r", "ѵ": "v", "ү": "y", "ҽ": "e", "ӕ": "ae",
    # Greek
    "α": "a", "β": "b", "ε": "e", "η": "n", "ι": "i", "κ": "k", "ν": "v", "ο": "o",
    "ρ": "p", "τ": "t", "υ": "u", "χ": "x", "γ": "y", "ω": "w", "μ": "u", "ς": "c",
    "σ": "o", "ϲ": "c", "ϳ": "j",
    # Latin look-alikes
    "ı": "i", "ɑ": "a", "ɩ": "i", "ʟ": "l", "ꞵ": "b", "ɴ": "n", "ᴏ": "o", "ꜱ": "s",
    "ᴄ": "c", "ᴅ": "d", "ᴇ": "e", "ʀ": "r", "ᴛ": "t", "ᴜ": "u", "ᴠ": "v", "ᴡ": "w",
    "ᴢ": "z", "ʏ": "y", "ʜ": "h", "ᴋ": "k", "ᴍ": "m", "ᴘ": "p",
    # dash variants
    "‐": "-", "‑": "-", "‒": "-", "–": "-", "—": "-", "―": "-", "−": "-", "﹣": "-",
    "_": "-",
}


def _skeleton(text: str) -> str:
    decomposed = unicodedata.normalize("NFD", text)
    mapped = "".join(_UNICODE_CONFUSABLES.get(char, char) for char in decomposed)
    return unicodedata.normalize("NFD", mapped)


def _fold_once(text: str) -> str:
    normal = unicodedata.normalize("NFKC", text)
    visible = "".join(char for char in normal if unicodedata.category(char) != "Cf")
    folded = " ".join(visible.split()).casefold()
    skeleton = _skeleton(folded).casefold()
    stripped = "".join(char for char in unicodedata.normalize("NFD", skeleton) if unicodedata.category(char) != "Mn")
    return "".join(_CONFUSABLES.get(char, char) for char in stripped)


def identity_key(text: str) -> str:
    current = text
    for _ in range(4):
        nxt = _fold_once(current)
        if nxt == current:
            break
        current = nxt
    return current
