"""Compare UnvibeCode's shipped _PEM pattern with a suggested replacement.

Every case runs through the real shipreadyv2.redaction.redact_text() with the
pattern swapped in. Key bodies are random PEM-shaped base64 generated at run
time (the patterns only look at the format), so no key material is stored here.

usage: python compare_fix.py [--all]
"""
import base64
import os
import re
import sys

import shipreadyv2.redaction as R

sys.stdout.reconfigure(encoding="utf-8")
ESC_NL = chr(92) + "n"  # the two characters \ and n, as inside a string literal

SHIPPED = R._PEM

# Suggested: keep the complete-block branch (bounded), and replace `|\Z` with a
# branch that only consumes key-armor lines after a header that has no END.
_PEM_WRAP = r"""[ \t"'`+,;#*/]*"""
_PEM_EOL = r"(?:\r?\n|\\r\\n|\\n)"
SUGGESTED = re.compile(
    r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----"
    r"(?:"
    r"(?:(?!-----BEGIN ).){0,20000}?-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----"
    r"|(?:" + _PEM_EOL + r"(?:"
    + _PEM_WRAP + r"(?:(?:Proc-Type|DEK-Info): [^\r\n\\\"']*|[A-Za-z0-9+/=]{16,})" + _PEM_WRAP
    + r"|" + _PEM_WRAP + r"(?=\r?\n|\\[rn]|\Z)"
    r"))*"
    r")",
    re.S,
)
PATTERNS = (("shipped", SHIPPED), ("suggested", SUGGESTED))


def fake_pem(label, size, encrypted=False):
    body = base64.b64encode(os.urandom(size)).decode()
    lines = [f"-----BEGIN {label}PRIVATE KEY-----"]
    if encrypted:
        lines += ["Proc-Type: 4,ENCRYPTED", "DEK-Info: AES-128-CBC,0123456789ABCDEF0123456789ABCDEF", ""]
    lines += re.findall(".{1,64}", body)
    lines.append(f"-----END {label}PRIVATE KEY-----")
    return "\n".join(lines) + "\n"


KEYS = {
    "rsa-2048 pkcs8": fake_pem("", 1217),
    "rsa-2048 traditional": fake_pem("RSA ", 1191),
    "rsa traditional encrypted": fake_pem("RSA ", 1200, encrypted=True),
    "ec p-256": fake_pem("EC ", 121),
    "ec p-521 pkcs8 (short last line)": fake_pem("", 241),
    "ed25519 pkcs8": fake_pem("", 48),
    "openssh": fake_pem("OPENSSH ", 387),
}
CODE = "def transfer_funds(a, amount):\n    a.balance -= amount\n    return a\n"


def body_lines(pem):
    return [l for l in pem.splitlines() if l and "-----" not in l and ": " not in l]


def key_layouts(pem):
    lines, esc = pem.splitlines(), pem.replace("\n", ESC_NL)
    return {
        "raw file": pem,
        "raw + code after": pem + CODE,
        "CRLF": pem.replace("\n", "\r\n"),
        "str with \\n escapes": f'TEST_KEY = "{esc}"\n' + CODE,
        "PRIVATE_KEY = str": f'PRIVATE_KEY = "{esc}"\n' + CODE,
        "service-account dict": 'creds = {"type": "service_account", "private_key": "' + esc + '", "client_email": "x@y"}\n' + CODE,
        "JSON line": '  "private_key": "' + esc + '",\n  "client_id": "1"\n',
        "py implicit concat": "KEY = (\n" + "".join(f'    "{l}{ESC_NL}"\n' for l in lines) + ")\n" + CODE,
        "JS + concat": "const key =\n" + " +\n".join(f'  "{l}{ESC_NL}"' for l in lines) + ";\n" + CODE,
        "commented out": "".join(f"# {l}\n" for l in lines) + CODE,
        "YAML block": "tls:\n  material: |\n" + "".join(f"    {l}\n" for l in lines) + "next: 1\n",
        "trailing spaces": "".join(l + "  \n" for l in lines) + CODE,
        "markdown fence": "```\n" + pem + "```\nMore docs here.\n",
        "triple-quoted": 'K = """' + pem + '"""\n\ndef f():\n    return K\n',
        "truncated (chunk cut)": "\n".join(lines[:4]) + "\n",
        "truncated, escaped": f'TEST_KEY = "{ESC_NL.join(lines[:4])}',
    }


H = "-----BEGIN PRIVATE KEY-----"
CODE_CASES = {
    "constant then def": f'PEM_HEADER = "{H}"\n\ndef transfer_funds(account, amount):\n    account.balance -= amount\n    return account\n',
    "comment then code": f"# {H}\nx = compute()\nreturn_value = x\n",
    "startswith then pass/return": f'if s.startswith("{H}"):\n    pass\nreturn True\n',
    "docstring Args: lines": f'"""Expects a PEM.\n{H}\nArgs: pem text\nReturns: key object\n"""\ndef load(p):\n    return p\n',
    "type annotations": f'#   {H}\nname: str = "a"\nvalue: int = 3\n',
    "blank lines then code": f"# {H}\n\n\n\ndef keep_me():\n    return 1\n",
    "HTTP-style lines": f"# {H}\nContent-Type: text/plain\nreal_code = 1\n",
}


def run(pattern, text):
    original = R._PEM
    R._PEM = pattern
    try:
        return R.redact_text(text)
    finally:
        R._PEM = original


def leaked(out, pem):
    hits = 0
    for line in body_lines(pem):
        s = line.strip()
        if any(s[i:i + 10] in out for i in range(0, max(1, len(s) - 9), 5)):
            hits += 1
    return hits


totals = {name: {"leaks": 0, "eaten": 0} for name, _ in PATTERNS}
key_total = 0
for key_name, pem in KEYS.items():
    for layout, text in key_layouts(pem).items():
        key_total += 1
        cells = []
        for name, pattern in PATTERNS:
            n = leaked(run(pattern, text), pem)
            totals[name]["leaks"] += bool(n)
            cells.append(f"LEAK {n} lines" if n else "redacted")
        if "--all" in sys.argv or any("LEAK" in c for c in cells):
            print(f"{key_name + ': ' + layout:58} " + " | ".join(f"{c:16}" for c in cells))

for case, text in CODE_CASES.items():
    cells = []
    for name, pattern in PATTERNS:
        out = run(pattern, text)
        eaten = sum(1 for a, b in zip(text.splitlines(), out.splitlines()) if a != b and b.strip() == "<REDACTED_PRIVATE_KEY>")
        totals[name]["eaten"] += bool(eaten)
        cells.append(f"{eaten} lines eaten" if eaten else "code kept")
    print(f"{'code: ' + case:58} " + " | ".join(f"{c:16}" for c in cells))

print()
for name, t in totals.items():
    print(f"{name:10} key cases leaking: {t['leaks']}/{key_total}   code cases losing lines: {t['eaten']}/{len(CODE_CASES)}")
