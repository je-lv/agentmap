"""JSON and JSONL report writers."""
from __future__ import annotations

import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

from . import SCHEMA_VERSION


def write_findings_json(store, path) -> None:
    doc = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "manifest": store.read_manifest(),
        "findings": [f.to_dict() for f in store.findings()],
    }
    Path(path).write_text(json.dumps(doc, indent=2, ensure_ascii=False), encoding="utf-8")


def write_results_jsonl(store, path) -> None:
    src = store.run_dir / "results.jsonl"
    if src.exists():
        shutil.copyfile(src, path)
    else:
        Path(path).write_text("", encoding="utf-8")
