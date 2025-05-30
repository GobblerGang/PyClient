import os
import threading
from typing import Optional
from utils.crypto_utils import CryptoUtils

class MasterKey:
    """Secure master key storage in memory."""
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        """Thread-safe singleton pattern."""
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._key: Optional[bytes] = None # type: ignore
                cls._instance._lock = threading.Lock()
            return cls._instance
    
    def set_key(self, key: bytes):
        """Store key in memory."""
        with self._lock:
            self._key = key
    
    def get(self) -> bytes:
        """Retrieve key. Raises if not set."""
        with self._lock:
            if self._key is None:
                raise ValueError("Master key not set")
            return self._key
    
    def clear(self):
        """Securely wipe key from memory."""
        with self._lock:
            if self._key is not None:
                # Overwrite before deletion
                self._key = os.urandom(len(self._key))
                self._key = None
    
    def derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive a master key from a password and salt."""
        return CryptoUtils.derive_master_key(password, salt)
    
    # def encrypt_with_master_key(self, data: bytes, associated_data: bytes) -> bytes:
    #     """Encrypt data with the master key."""
    #     if self._key is None:
    #         raise ValueError("Master key not set")
    #     nonce, ciphertext = CryptoUtils.encrypt_with_key(data, self._key, associated_data)
    #     return nonce + ciphertext
    
    # def decrypt_with_master_key(self, encrypted_data: bytes, associated_data: bytes) -> bytes:
    #     """Decrypt data with the master key."""
    #     if self._key is None:
    #         raise ValueError("Master key not set")
    #     nonce = encrypted_data[:12]
    #     ciphertext = encrypted_data[12:]
    #     return CryptoUtils.decrypt_with_key(nonce, ciphertext, self._key, associated_data)
