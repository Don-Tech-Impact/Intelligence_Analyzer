# tests/unit/test_smoke.py
"""
Smoke tests — verify core modules import without crashing.
Replace with real tests as the codebase stabilizes.
"""
import importlib
import pytest


@pytest.mark.parametrize("module_path", [
    "src.core.config",
    "src.core.logging_config",
    "src.models.schemas",
])
def test_module_imports_cleanly(module_path):
    """Each core module must be importable without side effects."""
    mod = importlib.import_module(module_path)
    assert mod is not None
