"""Artifact IDs: strict canonical IDs and OCR-tolerant *candidates* (confirm via exists)."""
import re
import secrets

_OCR = str.maketrans({'o':'0','l':'1','i':'1','|':'1','s':'5','g':'9','z':'2','q':'9'})
# Enlarge only the six-character group for OCR confusions; preserve the design's boundaries.
_PATTERN = re.compile(r'(?<![0-9a-z])[aä]\s?#\s?([0-9a-folisgzq|]{6})(?![0-9a-z])', re.I)

def normalise(value):
    if not isinstance(value, str):
        raise ValueError('id must be a string')
    value = value.strip().lower()
    if value.startswith('a#'):
        value = value[2:]
    if not re.fullmatch(r'[0-9a-f]{6}', value):
        raise ValueError('id must contain exactly six hexadecimal digits')
    return value

def find_ids(text):
    return list(dict.fromkeys('a#' + m.group(1).lower().translate(_OCR) for m in _PATTERN.finditer(text)))

def new_id():
    """Local candidate for offline spool only; registry confirms/reserves uniqueness."""
    return secrets.token_hex(3)
