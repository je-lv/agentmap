import json
import os
import stat

import pytest

from agentmap.findings import make_finding
from agentmap.store import RunStore

AWS = "AKIA" + "ABCDEFGHIJKLMNOP"


class Obs:
    def __init__(self, data):
        self.data = data

    def to_dict(self):
        return {"kind": "t.test", "target": "http://h:1/", "data": self.data, "evidence": []}


def mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


def test_new_creates_private_dirs_and_unique_names(tmp_path):
    a = RunStore.new(tmp_path)
    b = RunStore.new(tmp_path)
    assert a.run_dir != b.run_dir
    assert mode(a.run_dir) == 0o700 and mode(a.run_dir / "evidence") == 0o700


def test_evidence_is_0600_deduped_and_cannot_traverse(tmp_path):
    s = RunStore.new(tmp_path)
    ref = s.write_evidence("../../evil name.json", b'{"k": "v"}')
    assert ref.startswith("evidence/") and ".." not in ref and "/" not in ref[len("evidence/"):]
    path = s.run_dir / ref
    assert path.read_bytes() == b'{"k": "v"}' and mode(path) == 0o600
    assert s.write_evidence("../../evil name.json", b'{"k": "v"}') == ref


def test_observations_and_findings_are_masked_on_disk(tmp_path):
    s = RunStore.new(tmp_path)
    s.add_observation(Obs({"text": f"key {AWS}"}))
    s.add_finding(make_finding("AM-A2A-006", "http://h:1/", "high", detail=f"found {AWS}"))
    disk = (s.run_dir / "results.jsonl").read_text() + (s.run_dir / "findings.jsonl").read_text()
    assert AWS not in disk and "AKIA…[20]" in disk
    assert s.observations()[0]["data"]["text"].startswith("key <aws_access_key:")
    assert s.findings()[0].rule_id == "AM-A2A-006"


def test_checkpoint_survives_reopen(tmp_path):
    s = RunStore.new(tmp_path)
    s.mark_done("10.0.0.1", 8000)
    s.mark_done("10.0.0.1", 8001)
    again = RunStore(s.run_dir)
    assert again.completed == {("10.0.0.1", 8000), ("10.0.0.1", 8001)}


def test_manifest_roundtrip_and_mode(tmp_path):
    s = RunStore.new(tmp_path)
    s.write_manifest({"tool": "agentmap", "level": "passive"})
    assert s.read_manifest() == {"tool": "agentmap", "level": "passive"}
    assert mode(s.run_dir / "run.json") == 0o600
    s.write_manifest({"tool": "agentmap", "level": "probe"})
    assert s.read_manifest()["level"] == "probe"


def test_reading_a_missing_manifest_gives_empty(tmp_path):
    assert RunStore.new(tmp_path).read_manifest() == {}


def test_open_raises_on_missing_run_json_instead_of_creating_the_dir(tmp_path):
    missing = tmp_path / "typo-run-dir"
    with pytest.raises(FileNotFoundError):
        RunStore.open(missing)
    assert not missing.exists()


def test_open_raises_on_missing_checkpoint_for_resume(tmp_path):
    # --resume requires checkpoint.jsonl specifically, not just any
    # previously-created run directory (e.g. one with only a manifest).
    s = RunStore.new(tmp_path)
    with pytest.raises(FileNotFoundError):
        RunStore.open(s.run_dir, require="checkpoint.jsonl")


def test_open_succeeds_when_the_required_marker_exists(tmp_path):
    s = RunStore.new(tmp_path)
    s.write_manifest({"tool": "agentmap"})
    reopened = RunStore.open(s.run_dir)
    assert reopened.run_dir == s.run_dir
    s.mark_done("10.0.0.1", 8000)
    resumed = RunStore.open(s.run_dir, require="checkpoint.jsonl")
    assert resumed.completed == {("10.0.0.1", 8000)}


def test_permissions_independent_of_umask(tmp_path):
    """Verify that all created files/dirs have exactly 0o600/0o700 regardless of umask."""
    old_umask = os.umask(0)
    try:
        s = RunStore.new(tmp_path)
        s.write_evidence("test.json", b'{"data": "value"}')
        s.add_observation(Obs({"text": "test"}))
        s.add_finding(make_finding("AM-A2A-006", "http://h:1/", "high", detail="test"))
        s.write_manifest({"tool": "agentmap"})

        # The per-run directory and evidence/ are locked to 0o700. The user-chosen output base is
        # deliberately NOT re-permissioned (it may be a shared/root-owned dir such as /tmp).
        assert mode(s.run_dir) == 0o700, f"run_dir: {oct(mode(s.run_dir))}"
        assert mode(s.run_dir / "evidence") == 0o700, f"evidence dir: {oct(mode(s.run_dir / 'evidence'))}"

        # Verify all files are exactly 0o600
        for evidence_file in (s.run_dir / "evidence").glob("*"):
            assert mode(evidence_file) == 0o600, f"evidence file {evidence_file.name}: {oct(mode(evidence_file))}"
        assert mode(s.run_dir / "results.jsonl") == 0o600
        assert mode(s.run_dir / "findings.jsonl") == 0o600
        assert mode(s.run_dir / "run.json") == 0o600
    finally:
        os.umask(old_umask)
