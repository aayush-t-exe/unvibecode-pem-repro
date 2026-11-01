# unvibecode-pem-repro

Reproduction for an UnvibeCode bug: a `-----BEGIN PRIVATE KEY-----` header with no END line makes the client's credential screening replace **everything after it** in the analysis request with `<REDACTED_PRIVATE_KEY>`, including code from other files.

Issue: <link to the GitHub issue>

## What is in here

| Path | What it shows |
|---|---|
| `fixture_bug/` | 5-file Flask shop. `shop/keys.py` has `PEM_HEADER = "-----BEGIN PRIVATE KEY-----"` |
| `fixture_control/` | Identical except that line is `"-----BEGIN " + "PRIVATE KEY-----"` (same string at runtime) |
| `probe_request.py` | Runs UnvibeCode's own Steps 01–02 locally and shows what screening does to each Step 03 request. No API calls |
| `check_public_repos.py` | Runs `redact_text` on three public files at pinned commits |
| `compare_fix.py` | Shipped `_PEM` vs a suggested replacement, through the real `redact_text()`. Key bodies are random and generated at run time |

## Run it

Requires Python 3.11+ and `pip install unvibecode==0.3.15`. On Windows, set `PYTHONUTF8=1` first, or the CLI crashes while printing progress (a separate, already reported issue).

```bash
# What the model receives (no API)
python probe_request.py fixture_bug out_bug
python probe_request.py fixture_control out_control

# Same pattern in public code (downloads 3 files)
python check_public_repos.py

# Shipped pattern vs suggested pattern
python compare_fix.py

# Full review (uses the hosted service)
python -m unvibecode review --repository fixture_bug
python -m unvibecode review --repository fixture_control
```

## Results (UnvibeCode 0.3.15, Windows 11, Python 3.11.9)

**Screening (deterministic)**

| | Chunks sent to the model | Lines replaced |
|---|---|---|
| `fixture_bug` | 2 of 4 (`shop/orders.py` and `shop/payments.py` gone) | 42 |
| `fixture_control` | 4 of 4 | 0 |
| komuw/sewer @ d12d5a2, request 1 | 20 of 44 (23 other files gone, from `crypto.py:310`) | 1,719 of 4,616 |

**Full review (model output varies; 3 bug runs, 2 control runs)**

| | `fixture_bug` | `fixture_control` |
|---|---|---|
| Files cited by workflows | `app.py` only (3/3) | all four files (2/2) |
| Final status | COMPLETE with shallow workflows (2/3), PARTIAL (1/3) | COMPLETE (2/2) |
| Refund risk finding | 0/3 | 1/2 |

**Single public files**

| File | Lines replaced |
|---|---|
| komuw/sewer `sewer/crypto.py` @ d12d5a2 | 49 of 368, from line 310 (a comment) |
| Tribler/py-ipv8 `ipv8/peer.py` @ 4a294ed | 129 of 234, from line 83 (a `startswith` check) |
| covert-encryption/covert `covert/pubkey.py` @ 96658bb | 81 of 247, from line 153 (a comparison) |

## Why

`shipreadyv2/redaction.py:34`:

```python
_PEM = re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----.*?(?:-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----|\Z)", re.S)
```

With no END line, the `|\Z` branch matches to the end of the input. `secure_transport.create_response()` screens the whole combined request, so the match runs across file boundaries. The only check afterwards compares line counts, and the placeholders keep the count the same.
