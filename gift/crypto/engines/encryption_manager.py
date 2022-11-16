from abc import ABC, abstractmethod
from io import BufferedReader, BufferedWriter

from gift.secrets.secrets_manager import SecretsManager


class EncryptionManager(ABC):
    def __init__(self, secret_manager: SecretsManager) -> None:
        self.secret_manager = secret_manager

    @abstractmethod
    def wrap(self, source: BufferedReader, sink: BufferedWriter, password_length: int = 30) -> None:
       pass
    @abstractmethod
    def unwrap(self, source: BufferedReader, sink: BufferedWriter) -> str | None:  
      pass