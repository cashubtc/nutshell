import pytest


# Skip the global mint_server fixture for lightning-specific tests
@pytest.fixture
def mint_server():
    yield None


@pytest.fixture(scope="session")
def mint():
    yield None
