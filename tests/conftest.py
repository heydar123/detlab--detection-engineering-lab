"""Shared objects that are slow to build. Each one is built once per test run."""

from pathlib import Path

import pytest

from detlab.app import Lab
from detlab.generate import generate
from detlab.models import prepare_events
from detlab.rules import load_rules

ROOT = Path(__file__).resolve().parents[1]
RULES_DIR = ROOT / "rules"


@pytest.fixture(scope="session")
def root():
    return ROOT


@pytest.fixture(scope="session")
def rules():
    return load_rules(RULES_DIR)


@pytest.fixture(scope="session")
def dataset():
    """The made-up logs at seed 7 for 14 days: (events, ground truth)."""
    events, truth = generate(seed=7, days=14)
    return prepare_events(events), truth


@pytest.fixture(scope="session")
def lab():
    """The whole lab with the replay of the real recordings. Takes several seconds; built once.

    Tests must only read from it. A test that changes the lab builds its own.
    """
    return Lab(RULES_DIR, 7, 14)
