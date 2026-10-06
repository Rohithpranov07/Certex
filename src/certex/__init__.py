"""CERTEX: a complexity-certifying regular-expression compiler."""

from certex.compiler import Compiled, compile
from certex.runtime.governor import MatchResult
from certex.runtime.governor import run as match

__version__ = "1.0.0"

__all__ = ["Compiled", "MatchResult", "__version__", "compile", "match"]
