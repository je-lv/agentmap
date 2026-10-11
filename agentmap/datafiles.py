"""Packaged YAML data: discovery paths, port presets, advisories."""
from __future__ import annotations

from functools import lru_cache
from importlib import resources

import yaml

from .targets import parse_ports


@lru_cache(maxsize=None)
def load(name: str):
    text = resources.files("agentmap.data").joinpath(f"{name}.yaml").read_text(encoding="utf-8")
    return yaml.safe_load(text)


def ports_presets() -> dict[str, list[int]]:
    specs = load("ports")["presets"]
    return {name: parse_ports(spec) for name, spec in specs.items()}
