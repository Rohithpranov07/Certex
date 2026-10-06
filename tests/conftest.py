import csv
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def load_d1() -> list[dict[str, str]]:
    with open(ROOT / "datasets" / "d1_redos.csv", newline="") as f:
        return list(csv.DictReader(f))


def load_d5() -> list[str]:
    with open(ROOT / "datasets" / "d5_base_paper.csv", newline="") as f:
        return [r["pattern"] for r in csv.DictReader(f)]


@pytest.fixture(scope="session")
def d1() -> list[dict[str, str]]:
    return load_d1()


@pytest.fixture(scope="session")
def d5() -> list[str]:
    return load_d5()
