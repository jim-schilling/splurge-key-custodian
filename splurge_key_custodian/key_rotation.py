#!/usr/bin/env python3
"""Key rotation functionality for the Splurge Key Custodian."""

# Re-export KeyRotationManager from the new services location for backward compatibility
from splurge_key_custodian.services.rotation.manager import KeyRotationManager

__all__ = ["KeyRotationManager"]
