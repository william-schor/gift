from gift.secrets.secrets_manager import SecretsManager


class PassthroughSecretsManager(SecretsManager):
    def create_secret(self, indentifer: str, pwd_length: int) -> str:
        return indentifer
    def read_secret(self, indentifer: str) -> str:
        return "secret"
    def delete_secret(self, identifier: str) -> None:
        return None
    def add_signature(self, indentifier: str, hash: str) -> str:
        return indentifier
    def read_signature(self, indentifier: str) -> str:
        return "signature"