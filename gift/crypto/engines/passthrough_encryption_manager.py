from abc import ABC, abstractmethod
from io import BufferedReader, BufferedWriter
import shutil

from gift.secrets.secrets_manager import SecretsManager

from gift.crypto.engines.encryption_manager import EncryptionManager


class PassthroughEncryptionManager(EncryptionManager):
    secret_manager: SecretsManager

    def wrap(self, source: BufferedReader, sink: BufferedWriter, password_length: int = 30) -> None:
       shutil.copyfileobj(source, sink)
       return None
    def unwrap(self, source: BufferedReader, sink: BufferedWriter) -> str | None:  
        shutil.copyfileobj(source, sink)
        return None