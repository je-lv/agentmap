from agentmap.analysis.secrets import find_secrets  # reused by leakscan; import check
import importlib.util
import sys
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "leakscan", Path(__file__).resolve().parent.parent / "scripts" / "leakscan.py")
leakscan = importlib.util.module_from_spec(SPEC)
sys.modules["leakscan"] = leakscan
SPEC.loader.exec_module(leakscan)

AWS = "AKIA" + "ABCDEFGHIJKLMNOP"


def test_clean_tree_has_no_findings(tmp_path):
    (tmp_path / "a.py").write_text("print('hello')\n")
    assert leakscan.scan_tree(tmp_path) == []


def test_absolute_home_path_is_flagged(tmp_path):
    # Assembled, not a single literal run: this test file ships in the public
    # export too, and leakscan.HOME_MARKER appearing contiguously anywhere in
    # this source (even in a comment) would make the leak scanner flag this
    # very file when it scans a copy of the test suite -- the same
    # self-matching bug this file exists to catch in scripts/leakscan.py.
    home_path = "# see /" + "home/someoperator/dev/agentmap for the original\n"
    (tmp_path / "a.py").write_text(home_path)
    findings = leakscan.scan_tree(tmp_path)
    assert any(leakscan.HOME_MARKER in f for f in findings)


def test_author_email_is_flagged_when_given(tmp_path):
    # A synthetic placeholder, not a real address: this file ships in the public
    # export, so it must never carry a real operator's email as literal text,
    # which would defeat the very leak this scanner exists to catch.
    email = "test.author@example.invalid"
    (tmp_path / "a.py").write_text(f"# contact {email}\n")
    assert leakscan.scan_tree(tmp_path, author_email=email) == \
        leakscan.scan_tree(tmp_path, author_email=email)
    assert leakscan.scan_tree(tmp_path, author_email=email) != []
    assert leakscan.scan_tree(tmp_path) == []


def test_secret_shaped_value_is_flagged(tmp_path):
    (tmp_path / "a.py").write_text(f"KEY = '{AWS}'\n")
    assert leakscan.scan_tree(tmp_path) != []


def test_internal_markers_are_flagged(tmp_path):
    # Assembled rather than literal, for the same self-matching reason noted
    # on the fixture above: two of leakscan.INTERNAL_MARKERS' exact entries
    # must never appear contiguously in this file's own source.
    text = "# TOD" + "O internal: ask about the os" + "ai scripts\n"
    (tmp_path / "a.py").write_text(text)
    assert leakscan.scan_tree(tmp_path) != []


def test_tooling_path_marker_is_flagged(tmp_path):
    # Exercises one more entry in leakscan.INTERNAL_MARKERS (a path fragment
    # naming the operator's directory layout) that the first-draft tuple had
    # omitted. Assembled, not literal, for the same self-matching reason as
    # the fixtures above.
    text = "# originally developed under ~/tool" + "ing/some-project\n"
    (tmp_path / "a.py").write_text(text)
    assert leakscan.scan_tree(tmp_path) != []


def test_binary_files_are_skipped_not_crashed_on(tmp_path):
    (tmp_path / "bin.dat").write_bytes(b"\x00\xff\xfe\x80")
    assert leakscan.scan_tree(tmp_path) == []
