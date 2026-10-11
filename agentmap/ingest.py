"""Read targets from other tools' output."""
from __future__ import annotations

import json
from pathlib import Path
from xml.etree import ElementTree as ET

from .targets import Target, expand_item


def _lines(path) -> list[str]:
    path = Path(path)
    if not path.exists():
        return []
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def from_nmap_xml(path) -> list[Target]:
    path = Path(path)
    if not path.exists():
        return []
    try:
        root = ET.fromstring(path.read_text(encoding="utf-8"))
    except ET.ParseError:
        return []
    out: list[Target] = []
    for host in root.findall("host"):
        addr = host.find("address")
        if addr is None or not addr.get("addr"):
            continue
        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is not None and state.get("state") == "open" and port.get("portid"):
                out.append(Target(addr.get("addr"), int(port.get("portid"))))
    return out


def from_httpx_jsonl(path) -> list[Target]:
    out: list[Target] = []
    for line in _lines(path):
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if not isinstance(row, dict):
            continue
        if isinstance(row.get("url"), str):
            out.extend(expand_item(row["url"]))
        elif isinstance(row.get("host"), str) and isinstance(row.get("port"), int):
            scheme = row.get("scheme") if row.get("scheme") in ("http", "https") else "http"
            out.append(Target(row["host"].lower(), row["port"], scheme, ""))
    return out


def from_naabu(path) -> list[Target]:
    out: list[Target] = []
    for line in _lines(path):
        try:
            row = json.loads(line)
        except ValueError:
            row = None
        if isinstance(row, dict) and isinstance(row.get("host"), str) and isinstance(row.get("port"), int):
            out.append(Target(row["host"].lower(), row["port"]))
            continue
        if row is None:
            try:
                for target in expand_item(line):
                    if target.port is not None:
                        out.append(target)
            except ValueError:
                continue
    return out
