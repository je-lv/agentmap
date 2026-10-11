# Before scanning anything you do not own

1. Confirm the written authorization covers the exact hosts and the exact
   dates you are about to scan. `run.json` records when a run happened; make
   sure that falls inside the agreed window.
2. Confirm your scanning source address: `curl -4 ifconfig.me`. If the client
   allowlists a specific IP and you scan from elsewhere, you get a clean
   report that found nothing, indistinguishable from an authorized, thorough
   scan.
3. Start at `--level passive`. Nothing beyond `probe` sends a single write,
   but `probe`'s `tools/list`/`resources/list` calls still reach whatever the
   server's unauthenticated surface allows; read `docs/RULES.md` for what each
   level does before running it against production.
4. `--level active` is gated behind `--acknowledge "I am authorized to test
   these targets"` for a reason: it sends requests designed to test whether
   access control actually works (wrong Origin, wrong bearer token). That is
   indistinguishable, from the target's point of view, from an attacker
   probing the same thing. Confirm this is in the rules of engagement before
   you pass that flag.
5. A target behind a CDN, reverse proxy or shared host may route unrelated
   services through the same IP as the one you were authorized to test. Scope
   is enforced per **hostname**; an IP you reach by resolving an in-scope name
   can still answer for services you were not authorized to touch. If you
   scan raw IPs instead of names, confirm IP ownership first.
6. `--rate` and `--time-limit` exist so a no-DoS clause or maintenance window
   can be honoured and evidenced; treat them as required on a live engagement,
   not optional.
