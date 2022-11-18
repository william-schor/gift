import base64
import os
from io import SEEK_SET, BufferedReader, BufferedWriter
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from gift.crypto.engines.aes_cbc_encryption_engine import AesCbcEncryptionEngine
from gift.crypto.engines.encryption_engine_builder import EncryptionEngineBuilder
from gift.secrets.dict_secrets_manager import DictSecretsManager
from gift.secrets.secrets_manager import SecretsManager


TEST_BLOCK_SIZE = 512

class TestAesCbcEncryptionEngine:
    @pytest.fixture
    def secrets_manager(self) -> DictSecretsManager:
        sm = DictSecretsManager()
        return sm
    @pytest.fixture
    def secret_name(self) -> str:
        return "secret1"
    @pytest.fixture
    def wrapper(self, secrets_manager: SecretsManager, secret_name: str) -> AesCbcEncryptionEngine:
        return AesCbcEncryptionEngine(
            secrets_manager,
            secret_name=secret_name
        )
    @pytest.fixture
    def unwrapper(self, secrets_manager: SecretsManager, wrapper: AesCbcEncryptionEngine) -> AesCbcEncryptionEngine:
        salt, secret_id = wrapper.get_public_key_components()
        return AesCbcEncryptionEngine(
            secrets_manager,
            salt=salt,
            secret_id=secret_id.decode()
        )

    @pytest.fixture
    def bytes_block(self) -> bytes:
        return os.urandom(TEST_BLOCK_SIZE)

    def test_get_public_key_components(self, wrapper: AesCbcEncryptionEngine) -> None:
        components = wrapper.get_public_key_components()
        assert len(components) == 2
        assert components[0] == wrapper.salt
        assert components[1] == wrapper.secret_id.encode()


    def test_encrypt_and_decrypt(self, bytes_block: bytes, wrapper: AesCbcEncryptionEngine, unwrapper: AesCbcEncryptionEngine) -> None:
        # we are not testing security features. Only basic IO and 
        # ensuring that each function is the inverse of the other.
        
        cipher = wrapper.encrypt(bytes_block)
        plaintext = unwrapper.decrypt(cipher)

        assert plaintext != cipher and plaintext == bytes_block