"""Engine profiles: functions replaying a target engine's own pattern rewrites."""

from __future__ import annotations

from collections.abc import Callable

from certex.frontend.ir import Node
from certex.profiles.cpython import cpython_profile
from certex.profiles.java import java_profile
from certex.profiles.pcre2 import pcre2_profile

PROFILES: dict[str, Callable[[Node], Node]] = {
    "none": lambda n: n,
    "cpython": cpython_profile,
    "pcre2": pcre2_profile,
    "java": java_profile,
}


def get_profile(name: str) -> Callable[[Node], Node]:
    try:
        return PROFILES[name]
    except KeyError:
        raise ValueError(
            f"unknown profile {name!r}; valid profiles: {', '.join(sorted(PROFILES))}"
        ) from None
