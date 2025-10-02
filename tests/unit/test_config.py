"""Tests confirming config module removal and consolidation."""

import pytest


class TestConfigRemoval:
    """Ensure the legacy config module is absent."""

    def test_config_module_absent(self) -> None:
        with pytest.raises(ModuleNotFoundError):
            __import__("splurge_key_custodian.config")
