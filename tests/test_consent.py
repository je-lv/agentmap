import pytest
from agentmap.consent import ACK_PHRASE, Refused, require_ack


def test_passive_and_probe_need_no_ack():
    assert require_ack("passive", None) is None
    assert require_ack("probe", None) is None


def test_active_with_exact_phrase_flag():
    ack = require_ack("active", ACK_PHRASE)
    assert ack["level"] == "active" and ack["phrase"] == ACK_PHRASE and ack["at"]


def test_phrase_is_case_insensitive_but_exact():
    assert require_ack("active", ACK_PHRASE.upper())
    with pytest.raises(Refused):
        require_ack("active", ACK_PHRASE + " please")


def test_active_without_flag_noninteractive_refused():
    with pytest.raises(Refused):
        require_ack("active", None, interactive=False)


def test_active_interactive_prompt():
    ack = require_ack("active", None, prompt_fn=lambda msg: ACK_PHRASE, interactive=True)
    assert ack["level"] == "active"
    with pytest.raises(Refused):
        require_ack("active", None, prompt_fn=lambda msg: "no", interactive=True)
