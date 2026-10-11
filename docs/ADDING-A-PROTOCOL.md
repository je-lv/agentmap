# Adding a protocol

A protocol plugin implements `agentmap.protocols.base.Protocol`:

- `name`: short identifier (used in `--protocols`, `Coverage.matched`, finding `protocol` field).
- `min_level`: the lowest `agentmap.levels` value at which `probe()` should run at all.
- `async probe(ep, ctx) -> list[Observation]`: all I/O goes through `ctx.http`
  (`agentmap.http.HttpClient`), which enforces scope, the rate limiter and the
  response size cap. Never open a socket directly.
- `analyze(observations) -> list[Finding]`: pure. No I/O. Build findings with
  `agentmap.findings.make_finding(rule_id, target, confidence, detail=..., evidence=...)`.

Steps:

1. Add rules to `agentmap/rules.py` with a new `AM-<PROTO>-NNN` prefix.
2. Add paths/constants the plugin needs to `agentmap/data/paths.yaml` under a
   new top-level key, loaded via `agentmap.datafiles.load("paths")`.
3. Write the plugin in `agentmap/protocols/<name>.py`, following
   `agentmap/protocols/a2a.py` as the simpler example and
   `agentmap/protocols/mcp.py` for a handshake-based protocol with its own
   level gating inside `probe()`.
4. Register it in `agentmap/app.py`'s `ALL_PROTOCOLS` dict.
5. Add a fake server (see `tests/fakeserver.py` and `tests/mcpfake.py`) and
   tests covering: a clean match, a non-matching catch-all server, a hostile
   body, and every new rule's trigger and non-trigger case.
6. Run `python scripts/gen_rules_doc.py > docs/RULES.md` and commit the result.

If the protocol has any state-changing operation (anything beyond reading a
document or listing a catalog), it must never be called by `probe()` at any
level without an explicit, separately reviewed decision extending the
`active`-level gate and the invariant tests in `tests/test_invariants.py`.
