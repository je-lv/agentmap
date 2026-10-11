import pytest
from fakeserver import FakeServer


@pytest.fixture
def fake():
    server = FakeServer().start()
    yield server
    server.stop()
