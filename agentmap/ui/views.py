"""Live scan view: a rounded panel in a TTY, one plain line per endpoint otherwise."""
from __future__ import annotations

import re
from dataclasses import dataclass

from rich import box
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..textsafe import printable
from .theme import STATE_STYLE, strip_ansi

_LOUD = {"open", "error"}

_SEV_STYLE = {
    "critical": "bold #ff3366", "high": "#ff6b4a", "medium": "#ff9500",
    "low": "#a855f7", "info": "grey58",
}


@dataclass
class Row:
    state: str
    netloc: str
    matched: str = ""
    elapsed: str = ""
    reason: str = ""


def _clean(value: object, limit: int = 300) -> str:
    # Strip ANSI first, then make printable (order matters: printable escapes non-printing chars,
    # so ANSI escapes would be doubly escaped if we didn't strip them first)
    if not value:
        return ""
    text = strip_ansi(str(value))
    return printable(text, limit=limit)


def _reason_cell(reason: str, reason_style) -> Text:
    # Colour the count in an "N findings" reason; leave everything else to reason_style.
    m = re.match(r"^(\d+) (findings?)$", reason or "")
    if m:
        t = Text(overflow="ellipsis", no_wrap=True)
        t.append(m.group(1), style="#00f0ff")
        t.append(f" {m.group(2)}")
        return t
    return Text(_clean(reason, 300), style=reason_style, overflow="ellipsis", no_wrap=True)


def build_row(row: Row) -> tuple:
    colour, glyph, label = STATE_STYLE[row.state]
    badge_style = f"{colour} reverse" if row.state in _LOUD else colour
    reason_style = "bold #ff3366" if row.state == "error" else (
        "grey50" if row.state not in _LOUD else None)
    return (
        Text(glyph, style=colour, justify="center"),
        Text(_clean(row.netloc, 60)),
        Text(f" {label} ", style=badge_style),
        Text(_clean(row.matched, 20), style="#00f0ff"),
        Text(_clean(row.elapsed, 10), justify="right"),
        _reason_cell(row.reason, reason_style),
    )


def plain_line(row: Row) -> str:
    _, _, label = STATE_STYLE[row.state]
    fields = [label, _clean(row.netloc, 60), _clean(row.matched, 20),
              _clean(row.elapsed, 10), _clean(row.reason, 300)]
    line = "  ".join(f for f in fields if f)
    # Ensure line doesn't exceed reasonable length (prevents long reason from bloating output)
    if len(line) >= 300:
        line = line[:299]
    return line


def render_panel(header: str, rows: list[Row], footer: str) -> Panel:
    table = Table.grid(padding=(0, 1), expand=True)
    table.add_column(justify="center", width=1)
    table.add_column(width=24, no_wrap=True)
    table.add_column(width=9, no_wrap=True)
    table.add_column(width=9, no_wrap=True)
    table.add_column(justify="right", width=6)
    table.add_column(ratio=1, overflow="ellipsis", no_wrap=True)
    for row in rows:
        table.add_row(*build_row(row))
    footer_r = footer if isinstance(footer, Text) else Text.from_markup(footer)
    body = Group(Text.from_markup(header), Text(""), table, Text(""), footer_r)
    return Panel(body, box=box.ROUNDED, border_style="grey35", padding=(0, 1),
                title="[grey42]scan[/]", title_align="left")


def footer_line(cov, summary: dict, elapsed: float) -> Text:
    """Summary footer. Counts are coloured; the elapsed time is left uncoloured on purpose."""
    t = Text()

    def count(n, label, style="#00f0ff"):
        if t.plain:
            t.append("  ")
        t.append(str(n), style=style)
        t.append(f" {label}")

    count(cov.endpoints_total, "endpoints")
    if cov.tcp_open:
        count(cov.tcp_open, "open")
    if cov.tcp_closed:
        count(cov.tcp_closed, "closed")
    if cov.errors:
        count(cov.errors, "error" if cov.errors == 1 else "errors")
    skipped = cov.skipped_scope + cov.skipped_resumed
    if skipped:
        count(skipped, "skipped")
    total = summary.get("total", 0)
    if total:
        t.append("  ")
        t.append(str(total), style="#00f0ff")
        t.append(" findings")
        by_sev = summary.get("by_severity", {})
        worst = next((s for s in ("critical", "high", "medium", "low")
                     if by_sev.get(s)), None)
        if worst:
            style = _SEV_STYLE.get(worst, "")
            t.append(" (")
            t.append(str(by_sev[worst]), style=style)
            t.append(f" {worst}", style=style)
            t.append(")")
    t.append("  ")
    t.append(f"{elapsed:.1f}s")  # intentionally uncoloured
    return t


def _collision_detail(findings: list) -> dict:
    """Map id(finding) -> its detail, but only for findings that share rule+title+target with
    another in the set. With the offending detail hidden from the title, these would otherwise look
    identical; the detail is shown dimmed as a discriminator just for them."""
    from collections import Counter
    keys = Counter((f.rule_id, f.title, f.target) for f in findings)
    return {id(f): f.detail for f in findings
            if f.detail and keys[(f.rule_id, f.title, f.target)] > 1}


def _host_block(console: Console, netloc: str, matched: list, findings: list) -> None:
    from ..findings import severity_rank  # local import avoids a module cycle
    colour, _glyph, _label = STATE_STYLE["open"]
    head = Text()
    head.append("[+] ", style=f"{colour} bold")
    head.append(_clean(netloc, 80))
    if matched:
        head.append("   [")
        head.append(", ".join(matched), style="#00f0ff")
        head.append("]")
    n = len(findings)
    head.append("   [")
    head.append(str(n), style="#00f0ff")
    head.append(f" finding{'' if n == 1 else 's'}]")
    console.print(head)
    disc = _collision_detail(findings)
    for f in sorted(findings, key=lambda f: (-severity_rank(f.severity), f.rule_id)):
        line = Text("      ")
        line.append(f"{f.severity:<9} ", style=_SEV_STYLE.get(f.severity, ""))
        line.append(f"{f.rule_id:<11} ", style="#7aa2f7")
        line.append(_clean(f.title, 120))
        d = disc.get(id(f))
        if d:
            line.append(f"  ({_clean(d, 60)})", style="grey42")
        console.print(line)


def print_grouped(console: Console, host_results: list, findings_by_host: dict,
                  show_all: bool = False) -> None:
    """Findings grouped per host after a range scan. host_results is an ordered list of
    (netloc, state, matched). By default only hosts with findings are shown; show_all also lists
    open hosts with no findings and closed hosts."""
    console.print("")
    printed = 0
    for netloc, state, matched in host_results:
        if state == "open":
            found = findings_by_host.get(netloc, [])
            if found or show_all:
                _host_block(console, netloc, matched, found)
                printed += 1
        elif state == "error" and show_all:
            colour, _glyph, _label = STATE_STYLE["error"]
            t = Text()
            t.append("[!] ", style=f"{colour} bold")
            t.append(_clean(netloc, 80))
            t.append("   error", style="grey50")
            console.print(t)
            printed += 1
        elif state == "closed" and show_all:
            t = Text()
            t.append("[-] ", style="grey42")
            t.append(_clean(netloc, 80), style="grey50")
            t.append("   no agent endpoint", style="grey42")
            console.print(t)
            printed += 1
    if printed == 0:
        console.print("no agent endpoints with findings", style="grey50")


def print_report_paths(console: Console, store, formats: str) -> None:
    """A clean, clickable file:// link per report. No local server: open report.html directly in a
    browser that can read the run directory (a Flatpak/Snap browser is sandboxed away from /tmp, so
    keep runs under your home directory with -o)."""
    wanted = {f.strip() for f in formats.split(",") if f.strip()}
    rd = store.run_dir.resolve()
    shown = [(name.rsplit(".", 1)[-1], rd / name)
             for name in ("report.html", "report.md", "findings.json")
             if name.rsplit(".", 1)[-1] in wanted and (rd / name).is_file()]
    if not shown:
        return
    console.print("\nReports:", style="grey50", markup=False)
    for fmt, path in shown:
        console.print(f"  {fmt:<4}  file://{path}", markup=False)


class ScanView:
    def __init__(self, console: Console | None = None) -> None:
        self.console = console or Console()
        self.is_tty = bool(self.console.is_terminal)
        self._rows: list[Row] = []
        self._header = ""
        self._live: Live | None = None

    def start(self, header: str) -> None:
        self._header = header
        if self.is_tty:
            self._live = Live(render_panel(header, [], ""), console=self.console,
                              refresh_per_second=5, transient=False)
            self._live.start()
        else:
            self.console.print(Text.from_markup(header))

    def update(self, row: Row) -> None:
        try:
            if self.is_tty:
                self._rows.append(row)
                if self._live:
                    self._live.update(render_panel(self._header, self._rows[-200:], ""))
            else:
                self.console.print(plain_line(row))
        except Exception:  # noqa: BLE001 - the display must never crash the scan
            pass

    def finish(self, cov, summary: dict, elapsed: float) -> None:
        try:
            footer = footer_line(cov, summary, elapsed) if cov is not None else ""
            if self.is_tty:
                if self._live:
                    self._live.update(render_panel(self._header, self._rows, footer))
                    self._live.stop()
            else:
                self.console.print(footer)
        except Exception:  # noqa: BLE001
            pass
