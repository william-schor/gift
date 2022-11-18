from io import BufferedReader, BufferedWriter

from gift.crypto.engines.encryption_engine import EncryptionEngine
from gift.secrets.secrets_manager import SecretsManager


class PassthroughEncryptionManager(EncryptionEngine):
    def __init__(self, secret_manager: SecretsManager) -> None:
        self.secret_manager = secret_manager
        self.SIGNATURE_LENGTH = 0

    def get_public_key_components(self) -> list[bytes]:
        return [b'']
    def get_secret_id(self) -> bytes:
        return b''
    def encrypt(self, chunk: bytes) -> bytes:
        return chunk
    def decrypt(self, chunk: bytes) -> bytes:
        return chunk
    def update_signature(self, full_block: bytes) -> None:
        pass
    def sign(self, sink: BufferedWriter) -> None:
        pass
    def verify_signature(self, source: BufferedReader, block_size: int) -> None:
        pass
    