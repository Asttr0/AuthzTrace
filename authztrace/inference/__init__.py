"""Source-aware authorization contract inference."""

from .compiler import compile_contract
from .discovery import discover_source
from .models import Discovery, Evidence, RouteEvidence, SourceSpan
from .review import UnresolvedPolicyError, read_decisions, review_policies, write_evidence

__all__ = [
    "Discovery",
    "Evidence",
    "RouteEvidence",
    "SourceSpan",
    "UnresolvedPolicyError",
    "compile_contract",
    "discover_source",
    "read_decisions",
    "review_policies",
    "write_evidence",
]
