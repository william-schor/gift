from abc import ABC, abstractmethod

VAULT = "FileWrap" # can be exposed as a setting later, but likely should not be dynamic

class SecretsManager(ABC):

    @abstractmethod
    def create_secret(self, indentifer: str, pwd_length: int) -> str:
        pass
    @abstractmethod
    def read_secret(self, indentifer: str):
        pass

    @abstractmethod
    def add_signature(self, indentifier: str, hash: str):
        pass
  
    @abstractmethod
    def get_signature(self, indentifier: str) -> str:
        pass