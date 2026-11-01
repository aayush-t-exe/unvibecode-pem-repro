"""Show what UnvibeCode's credential screening does to each Step 03 request (no API calls).

Runs the package's own Step 01 and Step 02 locally, builds every Step 03 request
with build_assembled_input(), then applies redact_text() exactly as
secure_transport.create_response() does before sending.

usage: python probe_request.py <repository> <out_dir>
"""
import contextlib
import io
import json
import re
import sys
from pathlib import Path

from shipreadyv2 import cli, customer_runner as cr
from shipreadyv2.redaction import redact_text

repo, out = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()
out.mkdir(parents=True, exist_ok=True)
CHUNK = re.compile(r"<<<CHUNK\s+(\{.*?\})>>>")

with cli.prepared_runtime_engine() as engine:
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        step1 = cr.import_module_from_path(engine / cr.FULL_ANALYSIS_FILES[0], "full_01")
        report_folder = cr.discover_report_folder(cr.run_step_one(step1, repo, out / "b"), out / "b")
        step2 = cr.import_module_from_path(engine / cr.FULL_ANALYSIS_FILES[1], "full_02")
        cr.run_step_two(step2, report_folder, engine)
        step3 = cr.import_module_from_path(engine / cr.FULL_ANALYSIS_FILES[2], "full_03")

    rows = [json.loads(line) for line in (report_folder / "shipreadyv2_pass1_llm_inputs.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
    shared = next(row for row in rows if "shared_context_text" in row)
    requests = [row for row in rows if "input_payload" in row]
    print(f"requests: {len(requests)}")

    for request in requests:
        assembled = step3.build_assembled_input(shared, request)
        sent = redact_text(assembled)
        before = [json.loads(m[1])["file"] for m in CHUNK.finditer(assembled)]
        after = [json.loads(m[1])["file"] for m in CHUNK.finditer(sent)]
        a_lines, s_lines = assembled.splitlines(), sent.splitlines()
        replaced = sum(1 for a, s in zip(a_lines, s_lines) if a != s and "<REDACTED_PRIVATE_KEY>" in s)
        print(f"\n{request['request_id']}: lines={len(a_lines)} chunks before={len(before)} after={len(after)} "
              f"lines replaced by <REDACTED_PRIVATE_KEY>={replaced}")
        if len(after) != len(before):
            first = next(i for i, (a, s) in enumerate(zip(a_lines, s_lines)) if a != s and "<REDACTED_PRIVATE_KEY>" in s)
            print(f"  wipe starts at line {first + 1}: {a_lines[first].strip()[:100]!r}")
            print(f"  files whose chunks the model never sees ({len(before) - len(after)} chunks): {sorted(set(before[len(after):]))}")
            (out / f"{request['request_id']}.assembled.txt").write_text(assembled, encoding="utf-8")
            (out / f"{request['request_id']}.sent.txt").write_text(sent, encoding="utf-8")
