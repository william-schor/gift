from gift.crypto.engines.aes_cbc_encryption_engine import AesCbcEncryptionEngine
from gift.secrets.secrets_manager import SecretsManager
from gift.crypto.engines.encryption_engine import EncryptionEngine

class EncryptionEngineBuilder:
    def __init__(self, secret_manager: SecretsManager, secret_length: int = 30) -> None:
        self.secret_manager = secret_manager
        self.secret_length = secret_length

    def build_wrapper(self, secret_name: str) -> EncryptionEngine:
        return AesCbcEncryptionEngine(
            self.secret_manager,
            secret_name=secret_name,
            secret_length=self.secret_length
        )
    def build_unwrapper(self, key_components: list[bytes]) -> EncryptionEngine:
        salt, secret_id = key_components
        return AesCbcEncryptionEngine(
            self.secret_manager,
            salt=salt,
            secret_id=secret_id.decode()
        )
