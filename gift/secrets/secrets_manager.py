from abc import ABC, abstractmethod

class SecretsManager(ABC):

    @abstractmethod
    def create_secret(self, indentifer: str, secret_length: int) -> str:
        pass
    @abstractmethod
    def read_secret(self, indentifer: str) -> str:
        pass
    @abstractmethod
    def delete_secret(self, identifier: str) -> None:
        pass
    @abstractmethod
    def add_signature(self, indentifier: str, hash: str) -> str:
        pass
    @abstractmethod
    def read_signature(self, indentifier: str) -> str:
        pass