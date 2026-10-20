from pathlib import Path

import pytest

from app.services.analyzer import analyze_email

FIXTURES = Path(__file__).parent / "fixtures"
MAX_BYTES = 15 * 1024 * 1024


@pytest.fixture
def load_fixture():
    def _load(name: str) -> bytes:
        return (FIXTURES / name).read_bytes()

    return _load


@pytest.fixture
def analyze_fixture(load_fixture):
    def _analyze(name: str):
        return analyze_email(load_fixture(name), name, MAX_BYTES)

    return _analyze
