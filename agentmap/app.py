"""agentmap CLI."""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import stat
import sys
import time
from urllib.parse import urlsplit
from pathlib import Path

from rich.console import Console

from . import __version__, datafiles
from .consent import Refused, require_ack
from .diff import compare
from .engine import Engine, ScanConfig
from .findings import REGISTRY, SEVERITIES, severity_rank
from .http import HttpClient, RateLimiter
from .ingest import from_httpx_jsonl, from_naabu, from_nmap_xml
from .protocols.a2a import A2AProtocol
from .protocols.mcp import MCPProtocol
from .report import summarize
from .report.html import render as render_html
from .report.json_out import write_findings_json, write_results_jsonl
from .report.markdown import render as render_md
from .scope import Scope
from .store import RunStore
from .targets import estimate_hosts, iter_targets, make_excluder, parse_ports, read_target_file
from .ui.views import Row, ScanView, print_grouped, print_report_paths

SUBCOMMANDS = {"scan", "diff", "report", "rules", "version"}
ALL_PROTOCOLS = {"a2a": A2AProtocol, "mcp": MCPProtocol}
LARGE_SCAN_THRESHOLD_HOSTS = 1024
MAX_HOSTS = 1 << 20


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agentmap",
                                     description="Discovery and risk assessment for A2A and MCP agent endpoints")
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="scan for A2A and MCP agent endpoints")
    scan.add_argument("-t", "--targets")
    scan.add_argument("-f", "--target-file")
    scan.add_argument("--stdin", action="store_true")
    scan.add_argument("--from-nmap")
    scan.add_argument("--from-httpx")
    scan.add_argument("--from-naabu")
    scan.add_argument("-p", "--ports")
    scan.add_argument("--protocols", default="a2a,mcp")
    scan.add_argument("--level", choices=("passive", "probe", "active"), default="passive")
    scan.add_argument("--acknowledge")
    scan.add_argument("--rate", type=float, default=50.0)
    scan.add_argument("--concurrency", type=int, default=64)
    scan.add_argument("--per-host", type=int, default=8)
    scan.add_argument("-T", "--timeout", type=float, default=5.0)
    scan.add_argument("--connect-timeout", type=float, default=1.5)
    scan.add_argument("--time-limit", type=float)
    scan.add_argument("--proxy")
    scan.add_argument("--header", action="append", default=[])
    scan.add_argument("--user-agent")
    scan.add_argument("--resolve", action="append", default=[])
    scan.add_argument("--auth-file")
    scan.add_argument("--exclude", action="append", default=[])
    scan.add_argument("--yes", action="store_true")
    scan.add_argument("-o", "--outdir", default="runs")
    scan.add_argument("--resume")
    scan.add_argument("--format", default="json,md,html")
    scan.add_argument("--fail-on", choices=SEVERITIES)
    scan.add_argument("--plain", action="store_true")
    scan.add_argument("--show-all", action="store_true",
                      help="also show closed and no-finding hosts, not just hosts with findings")
    scan.add_argument("-v", "--verbose", action="store_true", help="implies --show-all")
    scan.add_argument("-q", "--quiet", action="store_true")

    diff = sub.add_parser("diff", help="compare two runs")
    diff.add_argument("run_a")
    diff.add_argument("run_b")

    report = sub.add_parser("report", help="re-render a run's reports")
    report.add_argument("run_dir")
    report.add_argument("--format", default="json,md,html")

    rules = sub.add_parser("rules", help="list or explain rules")
    rules_sub = rules.add_subparsers(dest="rules_command")
    rules_sub.add_parser("list")
    explain = rules_sub.add_parser("explain")
    explain.add_argument("rule_id")

    sub.add_parser("version", help="print the version")
    return parser


def _parse_args(argv: list[str]) -> argparse.Namespace:
    argv = list(argv)
    if not argv or (argv[0] not in SUBCOMMANDS and argv[0] not in ("-h", "--help")):
        argv = ["scan", *argv]
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        args.command = "scan"
    return args


def _parse_resolve(items: list[str]) -> dict:
    out = {}
    for item in items:
        host, port, ip = item.rsplit(":", 2)
        out[(host, int(port))] = ip
    return out


def _load_auth_file(path: str) -> dict:
    """Read a JSON object of header name to string value. Refuses anything not
    exactly mode 0600: a file any other user or group member could read is not
    an acceptable place to keep bearer tokens or API keys."""
    p = Path(path)
    mode = stat.S_IMODE(os.stat(p).st_mode)
    if mode != 0o600:
        raise ValueError(f"{path} must be mode 0600 (is {oct(mode)})")
    data = json.loads(p.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not all(isinstance(v, str) for v in data.values()):
        raise ValueError(f"{path} must be a JSON object of header name to string value")
    return data


def _collect_raw_items(args) -> list[str]:
    """The raw target strings from -t/-f/--stdin, before any CIDR/range is expanded
    into one Target per host. Kept separate from the ingest (--from-*) sources and
    from expansion itself so the large-scan/hard-cap checks in _run_scan can look at
    a cheap size estimate (targets.estimate_hosts) before ever materializing a
    potentially huge host list in memory."""
    raw_items: list[str] = []
    if args.targets:
        raw_items += [s for s in args.targets.split(",") if s.strip()]
    if args.target_file:
        raw_items += read_target_file(args.target_file)
    if args.stdin:
        raw_items += [line.strip() for line in sys.stdin if line.strip()]
    return raw_items


def _collect_targets(raw_items: list[str], args) -> list:
    ingested = []
    if args.from_nmap:
        ingested += from_nmap_xml(args.from_nmap)
    if args.from_httpx:
        ingested += from_httpx_jsonl(args.from_httpx)
    if args.from_naabu:
        ingested += from_naabu(args.from_naabu)
    seen = set()
    targets = []
    for t in [*iter_targets(raw_items), *ingested]:
        if t not in seen:
            seen.add(t)
            targets.append(t)
    return targets


def _check_host_count(estimate: int, *, yes: bool) -> int | None:
    """None if the scan may proceed; otherwise the exit code to return."""
    if estimate > MAX_HOSTS:
        print(f"error: {estimate} hosts exceeds the hard cap of {MAX_HOSTS}", file=sys.stderr)
        return 2
    if estimate > LARGE_SCAN_THRESHOLD_HOSTS and not yes:
        print(f"error: {estimate} hosts exceeds {LARGE_SCAN_THRESHOLD_HOSTS}; pass --yes to proceed",
             file=sys.stderr)
        return 3
    return None


def _run_scan(args) -> int:
    raw_items = _collect_raw_items(args)

    # Cheap pre-check on the raw target strings (hostnames, CIDRs, ranges) before
    # any of them is expanded into one Target per host. A CIDR like /8 must be
    # rejected here, without first building a multi-million-entry list in memory
    # just to find out it should have been refused.
    if raw_items:
        code = _check_host_count(estimate_hosts(raw_items), yes=args.yes)
        if code is not None:
            return code

    targets = _collect_targets(raw_items, args)
    if not targets:
        print("error: no targets specified (use -t, -f, --stdin, or a --from-* ingest flag)",
             file=sys.stderr)
        return 2

    # Precise check on the fully expanded, deduplicated target set. This is the
    # authoritative gate (it also covers hosts added only via --from-* ingest,
    # which the pre-check above never sees) and must still run before any run
    # directory is created.
    code = _check_host_count(len({t.host for t in targets}), yes=args.yes)
    if code is not None:
        return code

    try:
        ack = require_ack(args.level, args.acknowledge,
                          prompt_fn=input, interactive=sys.stdin.isatty())
    except Refused as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3

    # --exclude is action="append", so each flag's own value may itself be a
    # comma-separated list (e.g. --exclude 10.0.0.5,10.0.0.6); split before
    # handing it to make_excluder, or a multi-host value is silently treated
    # as one literal hostname that can never match anything ("fails open").
    exclude_items = [item for raw in args.exclude for item in raw.split(",") if item.strip()]
    try:
        excluder = make_excluder(exclude_items) if exclude_items else None
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    scope_items = raw_items or [t.host for t in targets]
    scope = Scope.from_items(scope_items, excluder=excluder)

    headers = {}
    for item in args.header:
        name, _, value = item.partition(":")
        headers[name.strip()] = value.strip()
    if args.auth_file:
        try:
            headers.update(_load_auth_file(args.auth_file))
        except (ValueError, OSError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    try:
        resolve = _parse_resolve(args.resolve)
    except ValueError:
        print("error: --resolve must be host:port:ip", file=sys.stderr)
        return 2

    try:
        presets = datafiles.ports_presets()
        ports = parse_ports(args.ports or "agent-default", presets)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    plugin_names = [p.strip() for p in args.protocols.split(",") if p.strip()]
    unknown = set(plugin_names) - set(ALL_PROTOCOLS)
    if unknown:
        print(f"error: unknown protocol(s): {', '.join(sorted(unknown))}", file=sys.stderr)
        return 2
    plugins = [ALL_PROTOCOLS[name]() for name in plugin_names]

    # Nothing above this line may create a run directory: a refused scan (large-scan
    # threshold without --yes, or active level without acknowledgement) must leave no
    # trace of a run that never happened.
    if args.resume:
        try:
            store = RunStore.open(Path(args.resume), require="checkpoint.jsonl")
        except FileNotFoundError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    else:
        store = RunStore.new(Path(args.outdir))
    limiter = RateLimiter(args.rate)
    http_kwargs = {}
    if args.user_agent:
        http_kwargs["user_agent"] = args.user_agent
    http = HttpClient(scope, limiter, timeout=args.timeout, connect_timeout=args.connect_timeout,
                      headers=headers or None, proxy=args.proxy, resolve=resolve, **http_kwargs)
    cfg = ScanConfig(ports=ports, level=args.level, concurrency=args.concurrency,
                     per_host=args.per_host, connect_timeout=args.connect_timeout,
                     time_limit=args.time_limit, resolve=resolve)

    console = Console(force_terminal=False) if args.plain else Console()
    # The live panel shows discovery for every scan; findings then print grouped per host (one block
    # for a single target, one per host for a range). --show-all (or -v) also surfaces closed and
    # no-finding hosts, which are hidden by default to keep big ranges readable.
    show_all = args.show_all or args.verbose
    view = ScanView(console=console) if not args.quiet else None
    if view:
        view.start(f"[bold #00f0ff]agentmap[/] [grey50]level={args.level} "
                  f"targets={len(targets)} ports={len(ports)}[/]")

    findings_by_host: dict[str, list] = {}
    host_results: list[tuple[str, str, list]] = []

    def _netloc(target: str) -> str:
        return urlsplit(target).netloc or target

    def _host_key(host: str, port: int) -> str:
        return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"

    def on_event(kind, payload):
        if not view:
            return
        if kind == "finding":
            findings_by_host.setdefault(_netloc(payload.target), []).append(payload)
            return
        if kind == "done":
            host_results.append((_host_key(payload["host"], payload["port"]),
                                 payload["state"], payload.get("matched", [])))
            if payload["state"] in ("open", "error") or show_all:
                matched = ",".join(payload["matched"])
                reason = payload.get("message", "")
                if not reason and payload["findings"]:
                    reason = f"{payload['findings']} findings"
                # No per-host time: under concurrent scanning it just mirrors the total (which is
                # in the footer) rather than a real per-host latency.
                view.update(Row(payload["state"], f"{payload['host']}:{payload['port']}",
                               matched, "", reason))
        elif kind == "skipped_scope" and show_all:
            view.update(Row("scope", payload.netloc, reason="not in target scope"))
        elif kind == "skipped_resumed" and show_all:
            host, port = payload
            view.update(Row("resumed", f"{host}:{port}", reason="from previous run"))

    engine = Engine(cfg, scope, http, store, plugins, on_event=on_event)
    start = time.monotonic()
    try:
        cov = asyncio.run(engine.run(targets))
    finally:
        asyncio.run(http.aclose())
    elapsed = time.monotonic() - start

    manifest = {
        "tool": "agentmap", "version": __version__, "level": args.level,
        "targets": len(targets), "ports": len(ports), "protocols": plugin_names,
        "rate": args.rate, "concurrency": args.concurrency, "proxy": args.proxy,
        "resolve": [f"{h}:{p}={ip}" for (h, p), ip in resolve.items()],
        "header_names": sorted(headers), "scope": scope_items,
        "excluded": exclude_items, "acknowledgement": ack,
        "coverage": cov.to_dict(),
        "refused": scope.refused, "elapsed_seconds": round(elapsed, 3),
    }
    store.write_manifest(manifest)
    _write_reports(store, args.format)
    if view:
        view.finish(cov, summarize(store), elapsed)
    if not args.quiet:
        print_grouped(console, host_results, findings_by_host, show_all)
        print_report_paths(console, store, args.format)

    if args.fail_on:
        threshold = severity_rank(args.fail_on)
        if any(severity_rank(f.severity) >= threshold for f in store.findings()):
            return 1
    return 0


def _write_reports(store, formats: str) -> None:
    wanted = {f.strip() for f in formats.split(",") if f.strip()}
    if "json" in wanted:
        write_findings_json(store, store.run_dir / "findings.json")
        write_results_jsonl(store, store.run_dir / "results.jsonl.export")
    if "md" in wanted:
        (store.run_dir / "report.md").write_text(render_md(store), encoding="utf-8")
    if "html" in wanted:
        (store.run_dir / "report.html").write_text(render_html(store), encoding="utf-8")


def _run_diff(args) -> int:
    try:
        a = RunStore.open(Path(args.run_a))
        b = RunStore.open(Path(args.run_b))
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(compare(a, b), indent=2))
    return 0


def _run_report(args) -> int:
    try:
        store = RunStore.open(Path(args.run_dir))
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    _write_reports(store, args.format)
    return 0


def _run_rules(args) -> int:
    if args.rules_command == "explain":
        rule = REGISTRY.get(args.rule_id)
        if not rule:
            print(f"error: unknown rule {args.rule_id!r}", file=sys.stderr)
            return 2
        print(f"{rule.id}  {rule.title}")
        print(f"severity={rule.severity} level={rule.level} protocol={rule.protocol}")
        print(rule.description)
        print("Remediation:", rule.remediation)
        print("Rationale:", rule.rationale)
        for ref in rule.references:
            print("Reference:", ref)
        return 0
    for rule_id in sorted(REGISTRY):
        rule = REGISTRY[rule_id]
        print(f"{rule.id}  [{rule.severity:>8}] [{rule.level:>7}] {rule.title}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    try:
        if args.command == "scan":
            return _run_scan(args)
        if args.command == "diff":
            return _run_diff(args)
        if args.command == "report":
            return _run_report(args)
        if args.command == "rules":
            return _run_rules(args)
        if args.command == "version":
            print(__version__)
            return 0
        print("error: unknown command", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        raise
    except (OSError, ValueError) as exc:
        # A usage mistake (missing target file, invalid CIDR/port spec, bad
        # --resolve syntax reached some other way, etc.) must never surface
        # as an uncaught traceback exiting 1 -- that is the exact same exit
        # code --fail-on uses for "a finding was found," which would make a
        # CI script unable to tell a real finding from a typo.
        print(f"error: {exc}", file=sys.stderr)
        return 2


def run_cli() -> None:
    raise SystemExit(main())
