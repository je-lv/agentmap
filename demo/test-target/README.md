# test-target

A deliberately vulnerable A2A + MCP server, for testing agentmap itself.
Nothing it does is real. Run it, scan it, and confirm agentmap finds what
it's supposed to find.

## Run it

```sh
python3 demo/test-target/server.py
```

It prints the port it's listening on (default `8766`, override with `-p`)
and binds to `127.0.0.1` only. This server is intentionally vulnerable;
never bind it anywhere reachable from outside your own machine.

## Scan it

In another terminal:

```sh
agentmap -t 127.0.0.1 -p 8766 --level probe -o /tmp/agentmap-demo-run
```

## What you should see

A real scan against this target should report, at minimum:

- **A2A** (`http://127.0.0.1:8766/.well-known/agent-card.json`): no auth
  declared, a plain-HTTP interface, an injection-style phrase in a skill
  description, a credential-shaped value in the provider field, an
  unsigned card, and push notifications enabled with no auth.
- **MCP** (`http://127.0.0.1:8766/mcp`): no auth required, a high-risk
  `run_shell_command` tool (reported **critical**), an injection-style
  phrase in that same tool's description, and a secret embedded in it.

## Capture the flag

The secret embedded in the `run_shell_command` tool description is a flag,
`FLAG-7f3a9c2e-agentmap-found-me`. It is masked everywhere agentmap reports
findings (`findings.json`, `report.md`, `report.html`) by design: that's
the tool's own secret-masking working correctly, the same guarantee a real
secret gets.

To actually capture it, read the raw (unmasked) evidence agentmap keeps for
exactly this reason:

```sh
cat /tmp/agentmap-demo-run/*/evidence/*tools* | grep FLAG
```

If that shows you the flag, agentmap's detection, masking, and evidence
trail are all working end to end on your machine.
