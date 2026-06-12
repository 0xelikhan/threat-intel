"""
Public Pydantic request/response models — single import surface.

Historical note: these classes are defined in `main.py` where the
endpoints live. Physically relocating them would force every endpoint
declaration to update its annotation, which is a contract-affecting
churn change for what is effectively a re-organisation. This module
re-exports them via a lazy attribute hook so new code can write:

    from models import AnalyzeRequest

without taking the import-site risk. Both `from main import X` and
`from models import X` resolve to the same class object.

When you add a new request/response model, add it to `_MODEL_NAMES`
below so it shows up here too.
"""

from __future__ import annotations

from typing import Any


_MODEL_NAMES = (
    "AnalyzeRequest",
    "TaxiiPollRequest",
    "SettingsRequest",
    "DetectionRequest",
    "GTIScoreRequest",
    "LoginRequest",
    "ClarifyRequest",
    "ScanHashRequest",
    "ScanUrlRequest",
    "CustomRuleSave",
    "YaraHuntRequest",
    "ScanClarifyRequest",
    "ScanFeedbackRequest",
    "EmailParseRequest",
    "EmailComposeRequest",
    "EmailSendRequest",
    "EmailTemplateSave",
    "EmailComposeAIRequest",
    "EmailRemediateRequest",
)


def __getattr__(name: str) -> Any:
    """Lazy re-export. Defers the `from main import ...` so we don't
    create a circular import when this module is loaded during app
    bootstrap. Raises AttributeError for unknown names per PEP 562."""
    if name not in _MODEL_NAMES:
        raise AttributeError(f"module 'models' has no attribute {name!r}")
    import main as _main
    obj = getattr(_main, name)
    globals()[name] = obj   # cache for next access
    return obj


def __dir__() -> list[str]:
    return list(_MODEL_NAMES) + list(globals().keys())


__all__ = list(_MODEL_NAMES)
