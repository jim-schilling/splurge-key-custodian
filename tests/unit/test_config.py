"""Tests confirming config module removal and consolidation."""

import unittest


class TestConfigRemoval(unittest.TestCase):
	"""Ensure the legacy config module is absent."""

	def test_config_module_absent(self) -> None:
		with self.assertRaises(ModuleNotFoundError):
			__import__("splurge_key_custodian.config")


if __name__ == "__main__":
	unittest.main()
