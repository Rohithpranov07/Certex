import csv
from pathlib import Path

import pytest

from certex.frontend.desugar import desugar
from certex.frontend.ir import Node, strip_groups
from certex.frontend.parser import parse
from certex.profiles import get_profile

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


def core_of(p: str, profile: str = "cpython") -> Node:
    return strip_groups(desugar(get_profile(profile)(parse(p).tree)))
