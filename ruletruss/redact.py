"""Credential redaction. Configuration exports carry secrets; none of them may reach the screen, a log or an export."""
import re
import unicodedata

REDACTED = "<redacted>"

# (pattern, replacement). Each keeps the keyword so the line stays readable, and drops the secret itself.
# A secret's value: a quoted string (which may contain spaces) or one word. Matching only one word left the rest of a quoted secret in view.
_V = r"""(?:"[^"]*"|'[^']*'|\S+)"""

_PATTERNS = [
    # Cisco: "enable secret 5 $1$...", "username x password 7 0822...", "snmp-server community public RO"
    (re.compile(r"(?i)\b((?:enable\s+)?(?:secret|password)\s+(?:\d\s+)?)" + _V), r"\1" + REDACTED),
    (re.compile(r"(?i)\b(snmp-server\s+(?:community|host\s+\S+(?:\s+version\s+\S+)?)\s+)" + _V), r"\1" + REDACTED),
    (re.compile(r"(?i)\b(key(?:-string)?\s+(?:\d\s+)?)" + _V), r"\1" + REDACTED),
    (re.compile(r"(?i)\b(pre-shared-key(?:\s+(?:local|remote))?\s+)" + _V), r"\1" + REDACTED),
    (re.compile(r"(?i)\b(community-string|authentication-key|encryption-key)\s+" + _V), r"\1 " + REDACTED),
    # FortiOS: set password ENC xxx / set psksecret ENC xxx / set passwd ...
    (re.compile(r"(?i)\b(set\s+(?:password|passwd|psksecret|secret|private-key|community|auth-pwd|priv-pwd)\s+)(?:ENC\s+)?" + _V),
     r"\1" + REDACTED),
    # XML (PAN-OS, pfSense/OPNsense): <password>...</password> and friends
    (re.compile(r"(?is)(<(?:password|passwd|phash|secret|psk|pre-shared-key|key|private-key|community|bcrypt-hash|"
                r"authkey|privkey|auth-password|priv-password|apikey|api-key|token)[^>]*>)[^<]+(</)"),
     r"\1" + REDACTED + r"\2"),
    # A bare "community <value>" (SNMP) and "psk <value>"; keywords such as send-community are left alone
    (re.compile(r"(?i)(?<![\w-])(community|psk)(\s+(?:\d\s+)?)" + _V), r"\1\2" + REDACTED),
    # Generic "something: value" and "something=value" secrets
    (re.compile(r"(?i)\b((?:api[_-]?key|token|passwd|password|secret|psk)\s*[:=]\s*)" + _V), r"\1" + REDACTED),
]


def redact(text):
    """Return `text` with credentials replaced by a marker. Used for every line stored as evidence."""
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def single_line(text, limit=None):
    """Free text from an upload as one line of plain characters: line breaks, control, format (bidi) and separator characters
    become a space. Anything written into generated configuration text, a file name or a log line goes through this first."""
    text = "".join(" " if unicodedata.category(c)[0] == "C" or c in "\u2028\u2029\u0085" else c
                   for c in str(text))
    text = " ".join(text.split())
    return text if limit is None or len(text) <= limit else text[: limit - 1] + "\u2026"
