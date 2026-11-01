"""Run UnvibeCode's credential screening on three public files at pinned commits.

usage: python check_public_repos.py

Downloads each file from GitHub (nothing is stored in this repo), applies
shipreadyv2.redaction.redact_text exactly as the client does before sending
code for analysis, and reports how many lines were replaced.
"""
import sys
import urllib.request

from shipreadyv2.redaction import redact_text

FILES = [
    ("komuw/sewer", "d12d5a29b8dbf86f201d69b5321dce3a3fb13611", "sewer/crypto.py"),
    ("Tribler/py-ipv8", "4a294ed1e98eb113e664f96dc0e988739ab23bec", "ipv8/peer.py"),
    ("covert-encryption/covert", "96658bb4921af06293000ff2109d954efbf317b1", "covert/pubkey.py"),
]

sys.stdout.reconfigure(encoding="utf-8")
for repo, sha, path in FILES:
    url = f"https://raw.githubusercontent.com/{repo}/{sha}/{path}"
    source = urllib.request.urlopen(url, timeout=30).read().decode("utf-8")
    original = source.splitlines()
    screened = redact_text(source).splitlines()
    replaced = [i for i, line in enumerate(screened) if "<REDACTED_PRIVATE_KEY>" in line]
    first = replaced[0] if replaced else None
    print(f"{repo} {path} @ {sha[:7]}")
    print(f"  {len(replaced)} of {len(original)} lines replaced")
    if first is not None:
        print(f"  starting at line {first + 1}: {original[first].strip()}")
