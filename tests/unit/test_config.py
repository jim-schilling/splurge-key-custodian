"""Unit tests for the config module."""

import unittest
from unittest.mock import patch

from splurge_key_custodian.config import KeyCustodianConfig, DEFAULT_CONFIG


class TestKeyCustodianConfig(unittest.TestCase):
    """Unit tests for KeyCustodianConfig class."""

    def test_default_configuration(self):
        """Test default configuration values."""
        config = KeyCustodianConfig()
        
        # Security settings
        self.assertEqual(config.max_login_attempts, 5)
        self.assertEqual(config.lockout_duration, 300)
        self.assertEqual(config.failed_attempt_delay, 1)
        self.assertEqual(config.min_password_length, 32)
        self.assertEqual(config.min_iterations, 500000)
        self.assertEqual(config.default_iterations, 1000000)
        
        # Performance settings
        self.assertTrue(config.enable_caching)
        self.assertEqual(config.cache_size_limit, 1000)
        self.assertEqual(config.cache_ttl, 3600)
        
        # File settings
        self.assertTrue(config.atomic_write_enabled)
        self.assertTrue(config.backup_enabled)
        self.assertTrue(config.secure_permissions)
        
        # Validation settings
        self.assertEqual(config.max_input_length, 1000)
        self.assertEqual(config.allowed_control_chars, {'\t', '\n', '\r'})

    def test_custom_configuration(self):
        """Test custom configuration values."""
        config = KeyCustodianConfig(
            max_login_attempts=10,
            lockout_duration=600,
            failed_attempt_delay=2,
            min_password_length=16,
            min_iterations=600000,
            default_iterations=1200000,
            enable_caching=False,
            cache_size_limit=500,
            cache_ttl=1800,
            atomic_write_enabled=False,
            backup_enabled=False,
            secure_permissions=False,
            max_input_length=500,
            allowed_control_chars={' '}
        )
        
        # Security settings
        self.assertEqual(config.max_login_attempts, 10)
        self.assertEqual(config.lockout_duration, 600)
        self.assertEqual(config.failed_attempt_delay, 2)
        self.assertEqual(config.min_password_length, 16)
        self.assertEqual(config.min_iterations, 600000)
        self.assertEqual(config.default_iterations, 1200000)
        
        # Performance settings
        self.assertFalse(config.enable_caching)
        self.assertEqual(config.cache_size_limit, 500)
        self.assertEqual(config.cache_ttl, 1800)
        
        # File settings
        self.assertFalse(config.atomic_write_enabled)
        self.assertFalse(config.backup_enabled)
        self.assertFalse(config.secure_permissions)
        
        # Validation settings
        self.assertEqual(config.max_input_length, 500)
        self.assertEqual(config.allowed_control_chars, {' '})

    def test_allowed_control_chars_default(self):
        """Test that allowed_control_chars defaults to expected values."""
        config = KeyCustodianConfig()
        self.assertEqual(config.allowed_control_chars, {'\t', '\n', '\r'})

    def test_allowed_control_chars_custom(self):
        """Test custom allowed_control_chars."""
        custom_chars = {'\t', '\n', '\r', ' '}
        config = KeyCustodianConfig(allowed_control_chars=custom_chars)
        self.assertEqual(config.allowed_control_chars, custom_chars)

    def test_validation_max_login_attempts_too_low(self):
        """Test validation of max_login_attempts being too low."""
        with self.assertRaises(ValueError) as cm:
            KeyCustodianConfig(max_login_attempts=0)
        self.assertIn("max_login_attempts must be at least 1", str(cm.exception))

    def test_validation_max_login_attempts_negative(self):
        """Test validation of max_login_attempts being negative."""
        with self.assertRaises(ValueError) as cm:
            KeyCustodianConfig(max_login_attempts=-1)
        self.assertIn("max_login_attempts must be at least 1", str(cm.exception))

    def test_validation_lockout_duration_too_low(self):
        """Test validation of lockout_duration being too low."""
        with self.assertRaises(ValueError) as cm:
            KeyCustodianConfig(lockout_duration=0)
        self.assertIn("lockout_duration must be at least 1 second", str(cm.exception))

    def test_validation_lockout_duration_negative(self):
        """Test validation of lockout_duration being negative."""
        with self.assertRaises(ValueError) as cm:
            KeyCustodianConfig(lockout_duration=-1)
        self.assertIn("lockout_duration must be at least 1 second", str(cm.exception))

    def test_validation_min_password_length_too_low(self):
        """Test validation of min_password_length being too low."""
        with self.assertRaises(ValueError) as cm:
            KeyCustodianConfig(min_password_length=7)
        self.assertIn("min_password_length must be at least 8", str(cm.exception))

    def test_validation_min_password_length_negative(self):
        """Test validation of min_password_length being negative."""
        with self.assertRaises(ValueError) as cm:
            KeyCustodianConfig(min_password_length=-1)
        self.assertIn("min_password_length must be at least 8", str(cm.exception))

    def test_validation_min_iterations_too_low(self):
        """Test validation of min_iterations being too low."""
        with self.assertRaises(ValueError) as cm:
            KeyCustodianConfig(min_iterations=99999)
        self.assertIn("min_iterations must be at least 100,000", str(cm.exception))

    def test_validation_min_iterations_negative(self):
        """Test validation of min_iterations being negative."""
        with self.assertRaises(ValueError) as cm:
            KeyCustodianConfig(min_iterations=-1)
        self.assertIn("min_iterations must be at least 100,000", str(cm.exception))

    def test_validation_default_iterations_less_than_min(self):
        """Test validation of default_iterations being less than min_iterations."""
        with self.assertRaises(ValueError) as cm:
            KeyCustodianConfig(min_iterations=600000, default_iterations=500000)
        self.assertIn("default_iterations must be at least min_iterations", str(cm.exception))

    def test_validation_cache_size_limit_too_low(self):
        """Test validation of cache_size_limit being too low."""
        with self.assertRaises(ValueError) as cm:
            KeyCustodianConfig(cache_size_limit=0)
        self.assertIn("cache_size_limit must be at least 1", str(cm.exception))

    def test_validation_cache_size_limit_negative(self):
        """Test validation of cache_size_limit being negative."""
        with self.assertRaises(ValueError) as cm:
            KeyCustodianConfig(cache_size_limit=-1)
        self.assertIn("cache_size_limit must be at least 1", str(cm.exception))

    def test_validation_cache_ttl_negative(self):
        """Test validation of cache_ttl being negative."""
        with self.assertRaises(ValueError) as cm:
            KeyCustodianConfig(cache_ttl=-1)
        self.assertIn("cache_ttl must be non-negative", str(cm.exception))

    def test_validation_max_input_length_too_low(self):
        """Test validation of max_input_length being too low."""
        with self.assertRaises(ValueError) as cm:
            KeyCustodianConfig(max_input_length=0)
        self.assertIn("max_input_length must be at least 1", str(cm.exception))

    def test_validation_max_input_length_negative(self):
        """Test validation of max_input_length being negative."""
        with self.assertRaises(ValueError) as cm:
            KeyCustodianConfig(max_input_length=-1)
        self.assertIn("max_input_length must be at least 1", str(cm.exception))

    def test_multiple_validation_errors(self):
        """Test that multiple validation errors are caught appropriately."""
        # This should fail on the first validation error encountered
        with self.assertRaises(ValueError) as cm:
            KeyCustodianConfig(
                max_login_attempts=0,
                lockout_duration=0,
                min_password_length=7
            )
        # Should fail on the first validation error
        self.assertIn("max_login_attempts must be at least 1", str(cm.exception))

    def test_edge_case_values(self):
        """Test edge case values that should be valid."""
        config = KeyCustodianConfig(
            max_login_attempts=1,
            lockout_duration=1,
            min_password_length=8,
            min_iterations=100000,
            default_iterations=100000,
            cache_size_limit=1,
            cache_ttl=0,
            max_input_length=1
        )
        
        # All values should be accepted
        self.assertEqual(config.max_login_attempts, 1)
        self.assertEqual(config.lockout_duration, 1)
        self.assertEqual(config.min_password_length, 8)
        self.assertEqual(config.min_iterations, 100000)
        self.assertEqual(config.default_iterations, 100000)
        self.assertEqual(config.cache_size_limit, 1)
        self.assertEqual(config.cache_ttl, 0)
        self.assertEqual(config.max_input_length, 1)

    def test_boolean_settings(self):
        """Test boolean configuration settings."""
        config = KeyCustodianConfig(
            enable_caching=False,
            atomic_write_enabled=False,
            backup_enabled=False,
            secure_permissions=False
        )
        
        self.assertFalse(config.enable_caching)
        self.assertFalse(config.atomic_write_enabled)
        self.assertFalse(config.backup_enabled)
        self.assertFalse(config.secure_permissions)

    def test_config_mutability_after_initialization(self):
        """Test that configuration values can be modified after initialization."""
        config = KeyCustodianConfig(max_login_attempts=10)
        
        # Dataclass is not frozen by default, so modification should work
        config.max_login_attempts = 20
        self.assertEqual(config.max_login_attempts, 20)

    def test_config_repr(self):
        """Test string representation of configuration."""
        config = KeyCustodianConfig(max_login_attempts=10, min_password_length=16)
        config_str = repr(config)
        
        # Should contain the class name and key parameters
        self.assertIn("KeyCustodianConfig", config_str)
        self.assertIn("max_login_attempts=10", config_str)
        self.assertIn("min_password_length=16", config_str)

    def test_config_equality(self):
        """Test configuration equality."""
        config1 = KeyCustodianConfig(max_login_attempts=10)
        config2 = KeyCustodianConfig(max_login_attempts=10)
        config3 = KeyCustodianConfig(max_login_attempts=20)
        
        self.assertEqual(config1, config2)
        self.assertNotEqual(config1, config3)

    def test_default_config_instance(self):
        """Test the DEFAULT_CONFIG instance."""
        # Should be an instance of KeyCustodianConfig
        self.assertIsInstance(DEFAULT_CONFIG, KeyCustodianConfig)
        
        # Should have default values
        self.assertEqual(DEFAULT_CONFIG.max_login_attempts, 5)
        self.assertEqual(DEFAULT_CONFIG.lockout_duration, 300)
        self.assertEqual(DEFAULT_CONFIG.min_password_length, 32)
        self.assertEqual(DEFAULT_CONFIG.min_iterations, 500000)
        self.assertEqual(DEFAULT_CONFIG.default_iterations, 1000000)
        self.assertTrue(DEFAULT_CONFIG.enable_caching)
        self.assertEqual(DEFAULT_CONFIG.cache_size_limit, 1000)
        self.assertEqual(DEFAULT_CONFIG.cache_ttl, 3600)
        self.assertTrue(DEFAULT_CONFIG.atomic_write_enabled)
        self.assertTrue(DEFAULT_CONFIG.backup_enabled)
        self.assertTrue(DEFAULT_CONFIG.secure_permissions)
        self.assertEqual(DEFAULT_CONFIG.max_input_length, 1000)
        self.assertEqual(DEFAULT_CONFIG.allowed_control_chars, {'\t', '\n', '\r'})

    def test_config_copy(self):
        """Test that configurations can be copied."""
        import copy
        
        original = KeyCustodianConfig(max_login_attempts=10)
        copied = copy.copy(original)
        
        self.assertEqual(original, copied)
        self.assertIsNot(original, copied)

    def test_config_deep_copy(self):
        """Test that configurations can be deep copied."""
        import copy
        
        original = KeyCustodianConfig(
            max_login_attempts=10,
            allowed_control_chars={'a', 'b', 'c'}
        )
        deep_copied = copy.deepcopy(original)
        
        self.assertEqual(original, deep_copied)
        self.assertIsNot(original, deep_copied)
        self.assertIsNot(original.allowed_control_chars, deep_copied.allowed_control_chars)


if __name__ == "__main__":
    unittest.main()
