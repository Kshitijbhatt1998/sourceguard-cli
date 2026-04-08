"""Shannon entropy — flag high-entropy strings as potential unknown secrets."""

import math
import re

# Characters common in base64/hex secrets
_B64  = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
_HEX  = "0123456789abcdefABCDEF"

ENTROPY_THRESHOLD = 4.5   # bits per char; typical English text ~3.5, secrets ~5+
MIN_LENGTH        = 20    # ignore short tokens
MAX_LENGTH        = 120   # ignore very long prose strings


def _shannon(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


def _charset_ratio(s: str, charset: str) -> float:
    return sum(1 for c in s if c in charset) / len(s)


def high_entropy_strings(line):
    hits = []
    pat = re.compile(r"""['"]([A-Za-z0-9+/=_\-]{%d,%d})['"]|(?<![.\w])([A-Za-z0-9+/=_\-]{%d,%d})(?![.\w])""" % (MIN_LENGTH,MAX_LENGTH,MIN_LENGTH,MAX_LENGTH))
    for m in pat.finditer(line):
        token = m.group(1) or m.group(2)
        if not token: continue
        b64r = sum(1 for c in token if c in _B64)/len(token)
        hexr = sum(1 for c in token if c in _HEX)/len(token)
        if b64r < 0.6 and hexr < 0.8: continue
        e = _shannon(token)
        if e >= ENTROPY_THRESHOLD:
            hits.append({"token": token, "entropy": round(e,2), "start": m.start(), "end": m.end()})
    return hits