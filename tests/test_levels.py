import pytest
from agentmap.levels import LEVELS, rank, allows


def test_levels_order():
    assert LEVELS == ("passive", "probe", "active")


def test_rank_and_allows():
    assert rank("passive") < rank("probe") < rank("active")
    assert allows("active", "probe")
    assert allows("probe", "probe")
    assert not allows("passive", "probe")


def test_unknown_level_raises():
    with pytest.raises(ValueError):
        rank("loud")
