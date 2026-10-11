import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_readme_mentions_authorization_and_levels():
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "Authorization" in text
    for level in ("passive", "probe", "active"):
        assert level in text
    assert "agent-card.json" in text


def test_rules_doc_is_up_to_date():
    generated = subprocess.run(
        ["python3", "scripts/gen_rules_doc.py"], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout
    assert generated == (ROOT / "docs" / "RULES.md").read_text(encoding="utf-8")
