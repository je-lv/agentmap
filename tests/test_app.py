import argparse
import json
import os
import stat
import time

from cards import MODERN_CARD
from fakeserver import Reply
from mcpfake import serve_mcp

from agentmap.app import MAX_HOSTS, _check_host_count, _collect_raw_items, _collect_targets, main
from agentmap.targets import estimate_hosts


def test_scan_end_to_end_writes_reports_and_exits_zero(fake, tmp_path):
    fake.route("GET", "/.well-known/agent-card.json", Reply(200, MODERN_CARD))
    outdir = tmp_path / "runs"
    code = main(["-t", fake.host, "-p", str(fake.port), "-o", str(outdir), "--rate", "0"])
    assert code == 0
    runs = list(outdir.iterdir())
    assert len(runs) == 1
    run_dir = runs[0]
    assert (run_dir / "run.json").exists()
    findings = json.loads((run_dir / "findings.json").read_text())
    assert findings["schema_version"] == 1
    assert any(f["rule_id"] == "AM-A2A-001" for f in findings["findings"])
    assert (run_dir / "report.md").exists() and (run_dir / "report.html").exists()
    assert stat.S_IMODE(os.stat(run_dir).st_mode) == 0o700


def test_no_targets_is_a_usage_error(tmp_path):
    assert main(["-o", str(tmp_path / "runs")]) == 2


def test_missing_target_file_is_a_clean_exit_2_not_a_traceback(tmp_path, capsys):
    # A FileNotFoundError from read_target_file() used to propagate uncaught,
    # which Python reports with exit code 1 -- the same code --fail-on uses
    # for "a finding was found," making a CI script unable to tell a usage
    # typo from a real finding.
    missing = tmp_path / "nope.txt"
    code = main(["-f", str(missing), "-o", str(tmp_path / "runs")])
    assert code == 2
    err = capsys.readouterr().err
    assert "Traceback" not in err
    assert not (tmp_path / "runs").exists()


def test_invalid_cidr_target_is_a_clean_exit_2_not_a_traceback(tmp_path, capsys):
    # A ValueError from expanding an invalid CIDR target (e.g. a bad prefix
    # length) used to propagate uncaught the same way, with the same
    # exit-code-1-vs-fail-on ambiguity.
    code = main(["-t", "10.0.0.0/99", "-o", str(tmp_path / "runs")])
    assert code == 2
    err = capsys.readouterr().err
    assert "Traceback" not in err
    assert not (tmp_path / "runs").exists()


def test_fail_on_sets_exit_code_one(fake, tmp_path):
    # MODERN_CARD only ever produces info-severity findings (AM-A2A-001, AM-A2A-007:
    # it declares auth, TLS interfaces, no secrets, no push-without-auth), so "info"
    # is the threshold that is actually met here; it still exercises the >= severity
    # comparison and the exit-code mapping that --fail-on is responsible for.
    fake.route("GET", "/.well-known/agent-card.json", Reply(200, MODERN_CARD))
    code = main(["-t", fake.host, "-p", str(fake.port), "-o", str(tmp_path / "runs"),
                "--rate", "0", "--fail-on", "info"])
    assert code == 1


def test_clean_scan_with_fail_on_exits_zero(fake, tmp_path):
    code = main(["-t", fake.host, "-p", str(fake.port), "-o", str(tmp_path / "runs"),
                "--rate", "0", "--fail-on", "critical"])
    assert code == 0


def test_active_level_without_acknowledge_is_refused(fake, tmp_path):
    code = main(["-t", fake.host, "-p", str(fake.port), "-o", str(tmp_path / "runs"),
                "--rate", "0", "--level", "active"])
    assert code == 3
    # No run directory -- not even the --outdir base -- may exist: the refusal must
    # happen before RunStore.new()/RunStore() is ever called, so there is nothing to
    # list. (A bare .iterdir() would raise FileNotFoundError here, which is itself
    # evidence nothing was created.)
    runs_dir = tmp_path / "runs"
    assert not runs_dir.exists() or list(runs_dir.iterdir()) == []


def test_active_level_with_acknowledge_runs(fake, tmp_path):
    serve_mcp(fake)
    code = main(["-t", fake.host, "-p", str(fake.port), "-o", str(tmp_path / "runs"),
                "--rate", "0", "--level", "active",
                "--acknowledge", "I am authorized to test these targets"])
    assert code in (0, 1)
    run_dir = next((tmp_path / "runs").iterdir())
    manifest = json.loads((run_dir / "run.json").read_text())
    assert manifest["acknowledgement"]["level"] == "active"


def test_large_cidr_without_yes_is_refused(tmp_path):
    code = main(["-t", "10.0.0.0/21", "-o", str(tmp_path / "runs")])
    assert code == 3


def test_resume_flag_continues_a_previous_run(fake, tmp_path):
    fake.route("GET", "/.well-known/agent-card.json", Reply(200, MODERN_CARD))
    outdir = tmp_path / "runs"
    main(["-t", fake.host, "-p", str(fake.port), "-o", str(outdir), "--rate", "0"])
    run_dir = next(outdir.iterdir())
    code = main(["-t", fake.host, "-p", str(fake.port), "--rate", "0",
                "--resume", str(run_dir)])
    assert code == 0


def test_rules_list_and_explain():
    assert main(["rules", "list"]) == 0
    assert main(["rules", "explain", "AM-A2A-001"]) == 0
    assert main(["rules", "explain", "AM-NOPE-999"]) == 2


def test_version_and_help_exit_zero():
    assert main(["version"]) == 0
    try:
        main(["--help"])
    except SystemExit as exc:
        assert exc.code == 0


def test_diff_command_prints_json(fake, tmp_path, capsys):
    fake.route("GET", "/.well-known/agent-card.json", Reply(200, MODERN_CARD))
    outdir = tmp_path / "runs"
    main(["-t", fake.host, "-p", str(fake.port), "-o", str(outdir), "--rate", "0"])
    main(["-t", fake.host, "-p", str(fake.port), "-o", str(outdir), "--rate", "0"])
    run_a, run_b = sorted(outdir.iterdir())
    capsys.readouterr()  # discard the two scans' live-view output; isolate the diff's stdout
    code = main(["diff", str(run_a), str(run_b)])
    assert code == 0
    out = json.loads(capsys.readouterr().out)
    assert "new_findings" in out


def test_report_command_rerenders_from_a_run_dir(fake, tmp_path):
    fake.route("GET", "/.well-known/agent-card.json", Reply(200, MODERN_CARD))
    outdir = tmp_path / "runs"
    main(["-t", fake.host, "-p", str(fake.port), "-o", str(outdir), "--rate", "0"])
    run_dir = next(outdir.iterdir())
    (run_dir / "report.html").unlink()
    code = main(["report", str(run_dir), "--format", "html"])
    assert code == 0 and (run_dir / "report.html").exists()


def test_report_on_typo_dir_is_a_clean_exit_2_not_a_silent_create(tmp_path):
    missing = tmp_path / "typo-run-dir"
    code = main(["report", str(missing)])
    assert code == 2
    assert not missing.exists()


def test_diff_on_typo_dirs_is_a_clean_exit_2_not_a_silent_create(tmp_path):
    a, b = tmp_path / "typo-a", tmp_path / "typo-b"
    code = main(["diff", str(a), str(b)])
    assert code == 2
    assert not a.exists() and not b.exists()


def test_resume_on_typo_dir_is_a_clean_exit_2_not_a_silent_create(tmp_path):
    missing = tmp_path / "typo-run-dir"
    code = main(["-t", "10.0.0.1", "-p", "443", "-o", str(tmp_path / "runs"),
                "--rate", "0", "--resume", str(missing)])
    assert code == 2
    assert not missing.exists()


def test_auth_file_must_be_mode_0600(fake, tmp_path):
    auth = tmp_path / "auth.json"
    auth.write_text('{"Authorization": "Bearer x"}')
    os.chmod(auth, 0o644)
    code = main(["-t", fake.host, "-p", str(fake.port), "-o", str(tmp_path / "runs"),
                "--rate", "0", "--auth-file", str(auth)])
    assert code == 2


def test_auth_file_with_valid_creds_does_not_cause_false_mcp_exposure(fake, tmp_path):
    # Regression test for the --auth-file false-positive: a strict-auth fake
    # server (requires the exact valid bearer token) scanned WITH --auth-file
    # set to that valid token must not report AM-MCP-002 ("completes
    # initialize without credentials") -- credentials WERE required and WERE
    # provided.
    serve_mcp(fake, auth="strict")
    auth = tmp_path / "auth.json"
    auth.write_text('{"Authorization": "Bearer good-token"}')
    os.chmod(auth, 0o600)
    outdir = tmp_path / "runs"
    code = main(["-t", fake.host, "-p", str(fake.port), "-o", str(outdir),
                "--rate", "0", "--level", "probe", "--auth-file", str(auth)])
    assert code == 0
    run_dir = next(outdir.iterdir())
    findings = json.loads((run_dir / "findings.json").read_text())
    assert not any(f["rule_id"] == "AM-MCP-002" for f in findings["findings"])


def test_strict_mcp_server_without_auth_file_is_also_not_falsely_flagged(fake, tmp_path):
    # Companion to the test above, against the very same strict-auth server:
    # scanning WITHOUT --auth-file at all must also not report AM-MCP-002,
    # since the endpoint genuinely requires auth either way. This guards
    # against a fix that only special-cases the --auth-file path.
    serve_mcp(fake, auth="strict")
    outdir = tmp_path / "runs"
    code = main(["-t", fake.host, "-p", str(fake.port), "-o", str(outdir),
                "--rate", "0", "--level", "probe"])
    assert code == 0
    run_dir = next(outdir.iterdir())
    findings = json.loads((run_dir / "findings.json").read_text())
    assert not any(f["rule_id"] == "AM-MCP-002" for f in findings["findings"])


def test_open_mcp_server_is_still_flagged_regardless_of_auth_file(fake, tmp_path):
    # True-positive guard: a genuinely open server (no auth enforced at all)
    # must still be flagged -- the --auth-file fix must not blind agentmap to
    # real exposure.
    serve_mcp(fake)
    outdir = tmp_path / "runs"
    code = main(["-t", fake.host, "-p", str(fake.port), "-o", str(outdir),
                "--rate", "0", "--level", "probe"])
    assert code == 0
    run_dir = next(outdir.iterdir())
    findings = json.loads((run_dir / "findings.json").read_text())
    assert any(f["rule_id"] == "AM-MCP-002" for f in findings["findings"])


def test_auth_file_with_valid_creds_does_not_cause_false_a2a_extended_exposure(fake, tmp_path):
    # Regression test for the same --auth-file false-positive on the A2A
    # side: the extended-card fetch (AM-A2A-009, "reachable without
    # credentials") must never itself carry --auth-file credentials. Here the
    # extended card genuinely requires the configured bearer token; scanning
    # WITH --auth-file set to that valid token must not report AM-A2A-009.
    card = dict(MODERN_CARD, capabilities={"extendedAgentCard": True})
    fake.route("GET", "/.well-known/agent-card.json", Reply(200, card))

    def ext_handler(req):
        if req.headers.get("authorization") == "Bearer good-token":
            return Reply(200, {"name": "full card"})
        return Reply(401, b"")

    fake.route("GET", "/extendedAgentCard", ext_handler)
    auth = tmp_path / "auth.json"
    auth.write_text('{"Authorization": "Bearer good-token"}')
    os.chmod(auth, 0o600)
    outdir = tmp_path / "runs"
    code = main(["-t", fake.host, "-p", str(fake.port), "-o", str(outdir), "--rate", "0",
                "--level", "active", "--acknowledge", "I am authorized to test these targets",
                "--auth-file", str(auth)])
    assert code == 0
    run_dir = next(outdir.iterdir())
    findings = json.loads((run_dir / "findings.json").read_text())
    assert not any(f["rule_id"] == "AM-A2A-009" for f in findings["findings"])


def test_same_extended_card_without_auth_file_is_also_not_falsely_flagged(fake, tmp_path):
    # Companion to the test above: scanning the same access-controlled
    # extended card WITHOUT --auth-file must also not report AM-A2A-009,
    # since no credentials means the fetch is correctly rejected either way.
    card = dict(MODERN_CARD, capabilities={"extendedAgentCard": True})
    fake.route("GET", "/.well-known/agent-card.json", Reply(200, card))

    def ext_handler(req):
        if req.headers.get("authorization") == "Bearer good-token":
            return Reply(200, {"name": "full card"})
        return Reply(401, b"")

    fake.route("GET", "/extendedAgentCard", ext_handler)
    outdir = tmp_path / "runs"
    code = main(["-t", fake.host, "-p", str(fake.port), "-o", str(outdir), "--rate", "0",
                "--level", "active", "--acknowledge", "I am authorized to test these targets"])
    assert code == 0
    run_dir = next(outdir.iterdir())
    findings = json.loads((run_dir / "findings.json").read_text())
    assert not any(f["rule_id"] == "AM-A2A-009" for f in findings["findings"])


def test_protocols_filter_restricts_to_a2a_only(fake, tmp_path):
    fake.route("GET", "/.well-known/agent-card.json", Reply(200, MODERN_CARD))
    serve_mcp(fake)
    outdir = tmp_path / "runs"
    main(["-t", fake.host, "-p", str(fake.port), "-o", str(outdir), "--rate", "0",
         "--protocols", "a2a"])
    run_dir = next(outdir.iterdir())
    findings = json.loads((run_dir / "findings.json").read_text())
    assert all(f["rule_id"].startswith("AM-A2A") for f in findings["findings"])


def test_plain_flag_avoids_ansi_on_stdout(fake, tmp_path, capsys):
    fake.route("GET", "/.well-known/agent-card.json", Reply(200, MODERN_CARD))
    main(["-t", fake.host, "-p", str(fake.port), "-o", str(tmp_path / "runs"),
         "--rate", "0", "--plain"])
    assert "\x1b[" not in capsys.readouterr().out


def test_check_host_count_boundary_matches_spec():
    # 1024 itself is allowed without --yes; one over requires it; the hard cap
    # refuses even with --yes.
    assert _check_host_count(1024, yes=False) is None
    assert _check_host_count(1025, yes=False) == 3
    assert _check_host_count(1025, yes=True) is None
    assert _check_host_count(MAX_HOSTS + 1, yes=True) == 2


def test_cidr_estimate_matches_actual_target_count_no_double_counting():
    # A /22 has 1022 usable IPv4 hosts. _run_scan computes a cheap pre-expansion
    # estimate (targets.estimate_hosts, over the raw strings) and a precise
    # post-expansion estimate (over the real, deduplicated Target list) and must
    # not add them together: doing so would silently double the host count and
    # require --yes for a scan well under the 1024 threshold.
    args = argparse.Namespace(targets="10.0.0.0/22", target_file=None, stdin=False,
                              from_nmap=None, from_httpx=None, from_naabu=None)
    raw_items = _collect_raw_items(args)
    targets = _collect_targets(raw_items, args)
    actual = len({t.host for t in targets})
    assert estimate_hosts(raw_items) == actual == 1022
    assert _check_host_count(actual, yes=False) is None


def test_scan_at_cidr_boundary_does_not_require_yes(tmp_path):
    # End-to-end version of the no-double-counting property above: a /22 (1022
    # usable hosts, below the 1024 threshold) must run to completion without
    # --yes. A doubled estimate (adding the pre-expansion and post-expansion
    # counts together, as an earlier draft of _run_scan did) pushes 1022 to
    # 2044 and wrongly demands --yes. The hosts are unreachable, so every
    # connection attempt fails fast; -q suppresses the per-endpoint output.
    outdir = tmp_path / "runs"
    code = main(["-t", "10.0.0.0/22", "-o", str(outdir), "--rate", "0",
                "--connect-timeout", "0.2", "--concurrency", "200", "-p", "443", "-q"])
    assert code == 0


def test_hard_cap_cidr_is_refused_without_enumerating(tmp_path):
    # A /8 (~16.7M hosts) must be refused by the cheap pre-check on the raw CIDR
    # string, before targets.iter_targets ever expands it into one Target per
    # host -- expanding it first would itself be the resource exhaustion this
    # cap exists to prevent. --yes must not override the hard cap either.
    outdir = tmp_path / "runs"
    start = time.monotonic()
    code = main(["-t", "10.0.0.0/8", "-o", str(outdir), "--yes"])
    elapsed = time.monotonic() - start
    assert code == 2
    assert elapsed < 5.0
    assert not outdir.exists()


def test_collect_targets_dedupes_across_sources_without_dropping_distinct(tmp_path):
    nmap_xml = tmp_path / "scan.xml"
    nmap_xml.write_text(
        '<nmaprun><host><address addr="10.0.0.9"/><ports>'
        '<port portid="443"><state state="open"/></port>'
        "</ports></host></nmaprun>"
    )
    args = argparse.Namespace(from_nmap=str(nmap_xml), from_httpx=None, from_naabu=None)
    # 10.0.0.9:443 is given by both -t and --from-nmap and must collapse to one
    # Target; 10.0.0.10:443 is only given by -t and must still appear.
    raw_items = ["10.0.0.9:443", "10.0.0.10:443"]
    targets = _collect_targets(raw_items, args)
    assert {(t.host, t.port) for t in targets} == {("10.0.0.9", 443), ("10.0.0.10", 443)}
    assert len(targets) == 2


def test_exclude_comma_separated_value_excludes_both_hosts(tmp_path):
    # --exclude is action="append", so a single flag's value may itself be a
    # comma-separated list; previously this was treated as one literal
    # (never-matching) hostname string, so neither host was actually excluded.
    outdir = tmp_path / "runs"
    code = main(["-t", "10.0.0.5,10.0.0.6,10.0.0.7", "-o", str(outdir), "--rate", "0",
                "--exclude", "10.0.0.5,10.0.0.6", "--connect-timeout", "0.2",
                "--concurrency", "50", "-p", "443", "-q"])
    assert code == 0
    run_dir = next(outdir.iterdir())
    manifest = json.loads((run_dir / "run.json").read_text())
    assert manifest["coverage"]["skipped_scope"] == 2
    assert manifest["excluded"] == ["10.0.0.5", "10.0.0.6"]


def test_exclude_invalid_cidr_is_a_clean_usage_error(tmp_path):
    outdir = tmp_path / "runs"
    code = main(["-t", "10.0.0.1", "-o", str(outdir), "--rate", "0",
                "--exclude", "10.0.0.0/99"])
    assert code == 2
    assert not outdir.exists()


def test_default_user_agent_is_sent_when_not_overridden(fake, tmp_path):
    # HttpClient defaults its user_agent kwarg to DEFAULT_UA; passing user_agent=None
    # explicitly (as happens if args.user_agent, unset, is forwarded unconditionally)
    # overrides that default and sends a None header, which httpx rejects outright.
    fake.route("GET", "/.well-known/agent-card.json", Reply(200, MODERN_CARD))
    code = main(["-t", fake.host, "-p", str(fake.port), "-o", str(tmp_path / "runs"), "--rate", "0"])
    assert code == 0
    sent = [r for r in fake.requests if r.path == "/.well-known/agent-card.json"]
    assert sent and sent[0].headers.get("user-agent", "").startswith("agentmap/")


def test_custom_user_agent_is_honoured(fake, tmp_path):
    fake.route("GET", "/.well-known/agent-card.json", Reply(200, MODERN_CARD))
    code = main(["-t", fake.host, "-p", str(fake.port), "-o", str(tmp_path / "runs"),
                "--rate", "0", "--user-agent", "custom-ua/9"])
    assert code == 0
    sent = [r for r in fake.requests if r.path == "/.well-known/agent-card.json"]
    assert sent and sent[0].headers.get("user-agent") == "custom-ua/9"
