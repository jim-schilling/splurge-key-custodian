"""Index service for managing credentials index operations."""

import logging
from typing import Any, Dict

from splurge_key_custodian.exceptions import FileOperationError
from splurge_key_custodian.file_manager import FileManager
from splurge_key_custodian.models import CredentialsIndex

logger = logging.getLogger(__name__)


class IndexService:
    """Service for managing credentials index operations."""

    def __init__(self, file_manager: FileManager):
        """Initialize the index service.
        
        Args:
            file_manager: File manager instance
        """
        self._file_manager = file_manager

    def load_index(self) -> CredentialsIndex:
        """Load the credentials index.
        
        Returns:
            CredentialsIndex object
            
        Raises:
            FileOperationError: If index file operations fail
        """
        try:
            index = self._file_manager.read_credentials_index()
            if not index:
                # Check if there are credential files that need to be indexed
                credential_files = self._file_manager.list_credential_files()
                if credential_files:
                    # Auto-rebuild index from existing credential files
                    logger.info("Index file missing but credential files found, rebuilding index")
                    self.rebuild_index()
                    index = self._file_manager.read_credentials_index()
                else:
                    # Create empty index if no credential files exist
                    index = CredentialsIndex(credentials={})
            return index
        except Exception as e:
            logger.error(f"Failed to load credentials index: {e}")
            raise FileOperationError(f"Failed to load credentials index: {e}") from e

    def save_index(self, index: CredentialsIndex) -> None:
        """Save the credentials index.
        
        Args:
            index: CredentialsIndex object to save
            
        Raises:
            FileOperationError: If index file operations fail
        """
        try:
            self._file_manager.save_credentials_index(index)
            logger.debug("Credentials index saved successfully")
        except Exception as e:
            logger.error(f"Failed to save credentials index: {e}")
            raise FileOperationError(f"Failed to save credentials index: {e}") from e

    def add_credential_to_index(
        self,
        key_id: str,
        name: str,
        metadata: Dict[str, Any] | None = None
    ) -> None:
        """Add a credential to the index.
        
        Args:
            key_id: Key ID of the credential
            name: Name of the credential
            metadata: Additional metadata (optional)
            
        Raises:
            FileOperationError: If index operations fail
        """
        index = self.load_index()
        
        # Add credential to index (CredentialsIndex expects key_id -> name mapping)
        index.add_credential(key_id, name)
        
        self.save_index(index)
        
        logger.debug(f"Added credential {key_id} to index", extra={
            "key_id": key_id,
            "name": name,
            "event": "credential_indexed"
        })

    def remove_credential_from_index(self, key_id: str) -> None:
        """Remove a credential from the index.
        
        Args:
            key_id: Key ID of the credential to remove
            
        Raises:
            FileOperationError: If index operations fail
        """
        index = self.load_index()
        
        if key_id in index.credentials:
            del index.credentials[key_id]
            self.save_index(index)
            
            logger.debug(f"Removed credential {key_id} from index", extra={
                "key_id": key_id,
                "event": "credential_deindexed"
            })

    def update_credential_in_index(
        self,
        key_id: str,
        name: str | None = None,
        metadata: Dict[str, Any] | None = None
    ) -> None:
        """Update a credential in the index.
        
        Args:
            key_id: Key ID of the credential
            name: New name for the credential (optional)
            metadata: New metadata (optional)
            
        Raises:
            FileOperationError: If index operations fail
        """
        index = self.load_index()
        
        if key_id not in index.credentials:
            raise FileOperationError(f"Credential {key_id} not found in index")
        
        # Update credential in index (only name is stored in CredentialsIndex)
        if name is not None:
            index.update_credential_name(key_id, name)
        
        self.save_index(index)
        
        logger.debug(f"Updated credential {key_id} in index", extra={
            "key_id": key_id,
            "name": name,
            "event": "credential_index_updated"
        })

    def get_credential_from_index(self, key_id: str) -> Dict[str, Any] | None:
        """Get a credential from the index.
        
        Args:
            key_id: Key ID of the credential
            
        Returns:
            Dictionary with credential index data or None if not found
        """
        index = self.load_index()
        name = index.get_name(key_id)
        if name is None:
            return None
        return {"name": name}

    def list_credentials_from_index(self) -> Dict[str, Dict[str, Any]]:
        """List all credentials from the index.
        
        Returns:
            Dictionary mapping key_id to credential index data
        """
        index = self.load_index()
        result = {}
        for key_id, name in index.credentials.items():
            result[key_id] = {"name": name}
        return result

    def search_credentials_by_name(self, name_pattern: str) -> Dict[str, Dict[str, Any]]:
        """Search credentials by name pattern.
        
        Args:
            name_pattern: Name pattern to search for (case-insensitive)
            
        Returns:
            Dictionary mapping key_id to credential index data for matching credentials
        """
        index = self.load_index()
        matching_credentials = {}
        
        name_pattern_lower = name_pattern.lower()
        for key_id, name in index.credentials.items():
            if name_pattern_lower in name.lower():
                matching_credentials[key_id] = {"name": name}
        
        return matching_credentials

    def get_index_statistics(self) -> Dict[str, Any]:
        """Get statistics about the credentials index.
        
        Returns:
            Dictionary with index statistics
        """
        index = self.load_index()
        
        total_credentials = len(index.credentials)
        
        # Get unique names
        unique_names = set(index.credentials.values())
        
        return {
            "total_credentials": total_credentials,
            "unique_names": len(unique_names),
            "index_size_bytes": len(str(index.credentials))
        }

    def rebuild_index(self) -> None:
        """Rebuild the credentials index from credential files.
        
        This method reads all credential files and rebuilds the index
        to ensure consistency between the index and actual credential files.
        
        Raises:
            FileOperationError: If index operations fail
        """
        try:
            # Get all credential files
            credential_files = self._file_manager.list_credential_files()
            
            # Create new index
            new_index = CredentialsIndex(credentials={})
            
            # Add each credential to the new index
            for key_id in credential_files:
                credential_file = self._file_manager.read_credential_file(key_id)
                if credential_file:
                    new_index.add_credential(key_id, credential_file.name)
            
            # Save new index
            self.save_index(new_index)
            
            logger.info("Credentials index rebuilt successfully", extra={
                "total_credentials": len(new_index.credentials),
                "event": "index_rebuilt"
            })
            
        except Exception as e:
            logger.error(f"Failed to rebuild credentials index: {e}")
            raise FileOperationError(f"Failed to rebuild credentials index: {e}") from e
