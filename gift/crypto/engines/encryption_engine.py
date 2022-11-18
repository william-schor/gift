from abc import ABC, abstractmethod
from io import BufferedReader, BufferedWriter

from gift.secrets.secrets_manager import SecretsManager

class EncryptionEngine(ABC):
    @abstractmethod
    def __init__(self, secret_manager: SecretsManager) -> None:
        self.secret_manager = secret_manager
        # Must be set by each implementation!
        self.SIGNATURE_LENGTH = 0
    @abstractmethod
    def get_public_key_components(self) -> list[bytes]:
        """This method is responsible for exposing key material (i.e. the salt) 
        that should be written to the file. Note that this should not include
        any secrets!!"""
        pass
    @abstractmethod
    def get_secret_id(self) -> bytes:
        """This method exposes the secret identifier to be saved to the file"""
        pass
    @abstractmethod
    def encrypt(self, chunk: bytes) -> bytes:
        pass
    @abstractmethod
    def decrypt(self, chunk: bytes) -> bytes:
        pass
    @abstractmethod
    def update_signature(self, full_block: bytes) -> None:
        pass
    @abstractmethod
    def sign(self, sink: BufferedWriter) -> None:
        pass
    @abstractmethod
    def verify_signature(self, source: BufferedReader, block_size: int) -> None:
        pass
    
