"""
Message encryption utilities for secure ARP chat.
"""

import base64
import os
import hashlib
from typing import Optional, Tuple

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

from config import settings


class MessageEncryption:
    """
    Handles encryption and decryption of chat messages.
    Uses Fernet (AES-128-CBC with HMAC) for symmetric encryption.
    """
    
    def __init__(self, key: Optional[bytes] = None):
        """
        Initialize encryption with a key.
        
        Args:
            key: Encryption key. If None, generates a new one.
        """
        if not CRYPTO_AVAILABLE:
            raise RuntimeError("cryptography library required for encryption")
        
        if key is None:
            self.key = Fernet.generate_key()
        else:
            self.key = key
        
        self._fernet = Fernet(self.key)
    
    @classmethod
    def from_password(cls, password: str, salt: Optional[bytes] = None) -> 'MessageEncryption':
        """
        Create encryption instance from a password.
        
        Args:
            password: Password string.
            salt: Salt for key derivation. If None, generates new salt.
        
        Returns:
            MessageEncryption instance.
        """
        if not CRYPTO_AVAILABLE:
            raise RuntimeError("cryptography library required for encryption")
        
        if salt is None:
            salt = os.urandom(settings.SALT_LENGTH)
        
        # Derive key from password
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=settings.KEY_DERIVATION_ITERATIONS,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        
        instance = cls(key)
        instance._salt = salt
        return instance
    
    @property
    def salt(self) -> Optional[bytes]:
        """Get the salt used for key derivation (if any)."""
        return getattr(self, '_salt', None)
    
    def encrypt(self, message: str) -> bytes:
        """
        Encrypt a message.
        
        Args:
            message: Plain text message.
        
        Returns:
            Encrypted bytes.
        """
        return self._fernet.encrypt(message.encode('utf-8'))
    
    def decrypt(self, encrypted: bytes) -> str:
        """
        Decrypt a message.
        
        Args:
            encrypted: Encrypted bytes.
        
        Returns:
            Decrypted plain text message.
        
        Raises:
            InvalidToken: If decryption fails (wrong key or corrupted data).
        """
        return self._fernet.decrypt(encrypted).decode('utf-8')
    
    def encrypt_bytes(self, data: bytes) -> bytes:
        """Encrypt raw bytes."""
        return self._fernet.encrypt(data)
    
    def decrypt_bytes(self, encrypted: bytes) -> bytes:
        """Decrypt to raw bytes."""
        return self._fernet.decrypt(encrypted)
    
    def get_key_fingerprint(self) -> str:
        """
        Get a fingerprint of the encryption key for verification.
        
        Returns:
            Hex string of key hash.
        """
        return hashlib.sha256(self.key).hexdigest()[:16]


class SimpleXOREncryption:
    """
    Simple XOR-based encryption for lightweight use.
    NOT cryptographically secure - for demonstration only!
    """
    
    def __init__(self, key: bytes):
        """
        Initialize with a key.
        
        Args:
            key: Key bytes for XOR operation.
        """
        if not key:
            raise ValueError("Key cannot be empty")
        self.key = key
    
    @classmethod
    def from_password(cls, password: str) -> 'SimpleXOREncryption':
        """Create instance from password."""
        # Use SHA256 hash of password as key
        key = hashlib.sha256(password.encode()).digest()
        return cls(key)
    
    def encrypt(self, data: bytes) -> bytes:
        """Encrypt data using XOR."""
        result = bytearray(len(data))
        key_len = len(self.key)
        
        for i, byte in enumerate(data):
            result[i] = byte ^ self.key[i % key_len]
        
        return bytes(result)
    
    def decrypt(self, data: bytes) -> bytes:
        """Decrypt data using XOR (same as encrypt)."""
        return self.encrypt(data)  # XOR is symmetric


def compress_message(message: str) -> bytes:
    """
    Simple message compression using a basic algorithm.
    Inspired by smaz compression from the arpchat project.
    
    Args:
        message: Message to compress.
    
    Returns:
        Compressed bytes.
    """
    # For simplicity, using zlib. In production, smaz-like
    # compression optimized for short strings would be better.
    import zlib
    return zlib.compress(message.encode('utf-8'), level=9)


def decompress_message(data: bytes) -> str:
    """
    Decompress a message.
    
    Args:
        data: Compressed bytes.
    
    Returns:
        Decompressed message string.
    """
    import zlib
    return zlib.decompress(data).decode('utf-8')


def generate_session_id() -> bytes:
    """
    Generate a random session ID.
    
    Returns:
        8 bytes of random data.
    """
    return os.urandom(settings.ID_SIZE)


def hash_message(message: str) -> bytes:
    """
    Generate a hash of a message for integrity verification.
    
    Args:
        message: Message to hash.
    
    Returns:
        SHA256 hash bytes.
    """
    return hashlib.sha256(message.encode('utf-8')).digest()


def verify_message_hash(message: str, expected_hash: bytes) -> bool:
    """
    Verify a message against its hash.
    
    Args:
        message: Message to verify.
        expected_hash: Expected hash bytes.
    
    Returns:
        True if hash matches, False otherwise.
    """
    return hash_message(message) == expected_hash
