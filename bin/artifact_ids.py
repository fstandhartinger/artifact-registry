"""Artifact IDs: strict canonical IDs and OCR-tolerant *candidates* (confirm via exists)."""
import re
from urllib.parse import unquote

_OCR = str.maketrans({'o':'0','l':'1','i':'1','|':'1','s':'5','g':'9','z':'2','q':'9'})
# Enlarge only the six-character group for OCR confusions; preserve the design's boundaries.
_PATTERN = re.compile(r'(?<![^\W_])[aä@]\s?[#＃]\s?([0-9a-folisgzq|]{6})(?![^\W_])', re.I)

def normalise(value):
    if not isinstance(value, str):
        raise ValueError('id must be a string')
    value = unquote(value).strip().lower()
    if value.startswith('a#'):
        value = value[2:]
    if not re.fullmatch(r'[0-9a-f]{6}', value):
        raise ValueError('id must contain exactly six hexadecimal digits')
    return value

def find_ids(text):
    candidates = [m.group(1).lower() for m in _PATTERN.finditer(text)]
    ordered = [v for v in candidates if re.fullmatch(r'[0-9a-f]{6}', v)]
    ordered += [v.translate(_OCR) for v in candidates if not re.fullmatch(r'[0-9a-f]{6}', v)]
    return list(dict.fromkeys('a#'+v for v in ordered))[:20]
