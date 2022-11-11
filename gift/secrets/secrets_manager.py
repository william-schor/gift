from abc import ABC, abstractmethod
from typing import NoReturn

class SecretsManager(ABC):
    @abstractmethod
    def get_secret(self, indentifer: str) -> str:
        pass
    @abstractmethod
    def create_secret(self, indentifer: str, pwd_length) -> str:
        pass
    