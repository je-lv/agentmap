"""Integration test for demo/test-target/server.py: a real scan against the
real demo server must find the findings and the flag the demo promises.
This is both a sanity check that agentmap works end to end on this machine,
and a regression test so the demo can't silently drift from what the
rules actually detect.
"""
from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

DEMO_DIR = Path(__file__).resolve().parent.parent / "demo" / "test-target"
sys.path.insert(0, str(DEMO_DIR))

from server import FLAG, Handler  # noqa: E402

from agentmap.app import main  # noqa: E402
from http.server import ThreadingHTTPServer  # noqa: E402


def start_demo_server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    import threading
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd


def test_probe_scan_finds_the_expected_rules_and_the_flag(tmp_path):
    httpd = start_demo_server()
    port = httpd.server_address[1]
    outdir = tmp_path / "runs"
    try:
        code = main([
            "-t", "127.0.0.1", "-p", str(port), "--level", "probe",
            "-o", str(outdir), "--rate", "0",
        ])
    finally:
        httpd.shutdown()
        httpd.server_close()

    assert code in (0, 1)
    run_dir = next(outdir.iterdir())
    findings = json.loads((run_dir / "findings.json").read_text())
    rule_ids = {f["rule_id"] for f in findings["findings"]}

    expected = {
        "AM-A2A-001", "AM-A2A-002", "AM-A2A-003", "AM-A2A-005",
        "AM-A2A-006", "AM-A2A-007", "AM-A2A-008",
        "AM-MCP-001", "AM-MCP-002", "AM-MCP-003", "AM-MCP-004", "AM-MCP-005",
    }
    missing = expected - rule_ids
    assert not missing, f"demo server no longer trips: {missing}"

    exec_finding = next(f for f in findings["findings"] if f["rule_id"] == "AM-MCP-003")
    assert exec_finding["severity"] == "critical"
    assert "run_shell_command" in exec_finding["detail"]

    # The flag is masked everywhere a report is read ...
    all_report_text = "\n".join(
        (run_dir / name).read_text()
        for name in ("findings.json", "report.md", "report.html")
    )
    assert FLAG not in all_report_text
    assert "generic_secret" in all_report_text

    # ... and present, unmasked, only in the 0600 evidence directory.
    evidence_dir = run_dir / "evidence"
    evidence_text = "\n".join(p.read_text() for p in evidence_dir.glob("*"))
    assert FLAG in evidence_text
    for p in evidence_dir.glob("*"):
        assert stat.S_IMODE(os.stat(p).st_mode) == 0o600
