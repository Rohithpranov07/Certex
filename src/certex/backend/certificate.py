"""HMAC-SHA256 signed complexity certificates, schema ``certex/1`` (TRD v1.1 §B.2.5)."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from typing import Any

SCHEMA = "certex/1"
_DEV_KEY = b"certex-development-key-not-secret"
_PREFIX = "hmac-sha256:"


def _key() -> tuple[bytes, bool]:
    """The signing key and whether it is the development key."""
    env = os.environ.get("CERTEX_KEY", "")
    if env:
        return env.encode("utf-8"), False
    return _DEV_KEY, True


def pattern_hash(pattern: str) -> str:
    return hashlib.sha256(pattern.encode("utf-8")).hexdigest()


def _canonical(body: dict[str, Any]) -> bytes:
    unsigned = {k: v for k, v in body.items() if k != "signature"}
    return json.dumps(unsigned, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")


def _mac(body: dict[str, Any], key: bytes) -> str:
    return _PREFIX + hmac.new(key, _canonical(body), hashlib.sha256).hexdigest()


def sign(body: dict[str, Any]) -> dict[str, Any]:
    key, dev = _key()
    cert = {k: v for k, v in body.items() if k != "signature"}
    cert["schema"] = SCHEMA
    cert["dev_key"] = dev
    cert["signature"] = _mac(cert, key)
    return cert


def verify(cert: dict[str, Any]) -> bool:
    sig = cert.get("signature")
    if not isinstance(sig, str):
        return False
    try:
        expected = _mac(cert, _key()[0])
    except (TypeError, ValueError):
        return False
    return hmac.compare_digest(sig.encode("utf-8"), expected.encode("utf-8"))


def budget_for(cert: dict[str, Any], n: int) -> int:
    """Step budget for an input of length ``n``: ``c * (m+1) * (n+1)**power + 64``."""
    b = cert["budget"]
    budget: int = int(b["c"]) * (int(b["m"]) + 1) * (n + 1) ** int(b["power"]) + 64
    return budget
