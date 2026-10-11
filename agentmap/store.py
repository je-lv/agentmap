"""Run directory: evidence, observations, findings, manifest, checkpoint."""
from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime
from pathlib import Path

from .analysis.secrets import mask_json, redact_text
from .findings import Finding


def _dir(path: Path) -> None:
    # Just ensure the directory exists. Used for the user-chosen output base, which we must not
    # re-permission: it may be a shared or root-owned directory such as /tmp, where chmod raises
    # EPERM. Only the per-run directory and evidence/ are locked down, by _private_dir below.
    path.mkdir(parents=True, exist_ok=True)


def _private_dir(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path, 0o700)


def _append_line(path: Path, obj: dict) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(obj, ensure_ascii=False) + "\n")
    os.chmod(path, 0o600)


class RunStore:
    def __init__(self, run_dir: Path) -> None:
        self.run_dir = Path(run_dir)
        _private_dir(self.run_dir)
        _private_dir(self.run_dir / "evidence")
        self.completed: set[tuple[str, int]] = self._load_completed()

    @classmethod
    def open(cls, run_dir: Path, *, require: str = "run.json") -> "RunStore":
        """Open a run directory that is supposed to already exist (report,
        diff, --resume) rather than the general constructor, which always
        mkdir(exist_ok=True)s -- silently creating an empty run directory
        from a typo'd path and letting `diff`/`report` "succeed" against
        nothing. `require` is the file that must already be on disk:
        run.json for report/diff, checkpoint.jsonl for --resume."""
        run_dir = Path(run_dir)
        if not (run_dir / require).is_file():
            raise FileNotFoundError(
                f"{run_dir} is not an existing run directory (missing {require})")
        return cls(run_dir)

    @classmethod
    def new(cls, base: Path) -> "RunStore":
        base = Path(base)
        _dir(base)
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        name, n = stamp, 1
        while (base / name).exists():
            n += 1
            name = f"{stamp}-{n}"
        return cls(base / name)

    # -- evidence ----------------------------------------------------------
    def write_evidence(self, name: str, data: bytes) -> str:
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", Path(name).name)[:80] or "evidence"
        ref = f"evidence/{hashlib.sha256(data).hexdigest()[:12]}-{safe}"
        path = self.run_dir / ref
        if not path.exists():
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
            os.chmod(path, 0o600)
        return ref

    # -- observations and findings ----------------------------------------
    def add_observation(self, obs) -> None:
        _append_line(self.run_dir / "results.jsonl", mask_json(obs.to_dict()))

    def add_finding(self, finding: Finding) -> None:
        row = finding.to_dict()
        row["detail"] = redact_text(row["detail"])
        _append_line(self.run_dir / "findings.jsonl", row)

    def observations(self) -> list[dict]:
        return self._read_lines("results.jsonl")

    def findings(self) -> list[Finding]:
        return [Finding.from_dict(row) for row in self._read_lines("findings.jsonl")]

    def _read_lines(self, name: str) -> list[dict]:
        path = self.run_dir / name
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]

    # -- checkpoint --------------------------------------------------------
    def _load_completed(self) -> set[tuple[str, int]]:
        return {(row["host"], int(row["port"])) for row in self._read_lines("checkpoint.jsonl")}

    def mark_done(self, host: str, port: int) -> None:
        self.completed.add((host, port))
        _append_line(self.run_dir / "checkpoint.jsonl", {"host": host, "port": port})

    # -- manifest ----------------------------------------------------------
    def write_manifest(self, manifest: dict) -> None:
        tmp = self.run_dir / "run.json.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, indent=2, ensure_ascii=False)
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.run_dir / "run.json")

    def read_manifest(self) -> dict:
        path = self.run_dir / "run.json"
        return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
