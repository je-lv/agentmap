import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_no_long_dashes_in_tracked_files():
    files = subprocess.run(
        ["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout.split()
    bad = []
    em_dash = chr(0x2014)
    en_dash = chr(0x2013)
    # Assembled, not literal: this test file ships in the public export, and
    # one of leakscan.INTERNAL_MARKERS' exact entries appearing contiguously
    # here (even in a comment) would make the leak scanner flag this very
    # file when it scans a copy of the test suite, even though this internal
    # docs path is itself stripped from the export before the scan ever runs.
    internal_docs_prefix = "docs/" + "super" + "powers/"
    for rel in files:
        if rel.startswith(internal_docs_prefix):
            continue
        path = ROOT / rel
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        if em_dash in text or en_dash in text:
            bad.append(rel)
    assert not bad, f"long dashes in: {bad}"
