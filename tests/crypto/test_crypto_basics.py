import os
import tempfile
from io import BytesIO

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from gift.crypto.encryption_manager import EncryptionManager
from gift.secrets.dict_secrets_manager import DictSecretsManager
from gift.secrets.secrets_manager import SecretsManager

TEST_BLOCK_SIZE = 512

class TestEncryptionManagerBasics:
    """
    These tests are for the helper functions and fundamentals of the EncryptionManager.
    """
    @pytest.fixture
    def password(self) -> str:
        return "password1"
    @pytest.fixture
    def secret_identifier(self) -> str:
        return "secret1"
    @pytest.fixture
    def secrets_manager(self) -> DictSecretsManager:
        sm = DictSecretsManager()
        return sm
    @pytest.fixture
    def encryption_manager(self, secrets_manager: SecretsManager) -> EncryptionManager:
        em = EncryptionManager(secrets_manager, TEST_BLOCK_SIZE)
        return em
    @pytest.fixture
    def secrets_manager_with_secret(self, secret_identifier: str) -> DictSecretsManager:
        sm = DictSecretsManager()
        sm.create_secret(secret_identifier, 20)
        return sm
    @pytest.fixture
    def initialized_encryption_manager(self, secrets_manager_with_secret: SecretsManager, secret_identifier: str) -> EncryptionManager:
        em = EncryptionManager(secrets_manager_with_secret, TEST_BLOCK_SIZE)
        em._init_key_material(secrets_manager_with_secret.read_secret(secret_identifier))
        return em
    @pytest.fixture
    def bytes_block(self) -> bytes:
        return os.urandom(TEST_BLOCK_SIZE)
    @pytest.fixture
    def filled_buffer(self, bytes_block: bytes) -> BytesIO:
        b = BytesIO()
        b.write(bytes_block)
        b.seek(0)
        return b
    @pytest.fixture
    def ten_blocks(self) -> list[bytes]:
        return [os.urandom(TEST_BLOCK_SIZE) for _ in range(10)]

    def test_init_key_material(self, encryption_manager: EncryptionManager, password: str):
        key, salt = encryption_manager._derive_key_from_password(password)
        encryption_manager._init_key_material(password, salt)
        
        assert encryption_manager.encryption_key == key[:16]
        assert encryption_manager.signing_key == key[16:]
        assert encryption_manager.salt == salt

        
    def test_encrypt_and_decrypt(self, bytes_block: bytes, initialized_encryption_manager: EncryptionManager):
        # we are not testing security features. Only basic IO and 
        # ensuring that each function is the inverse of the other.
        
        cipher = initialized_encryption_manager._encrypt(bytes_block)
        plaintext = initialized_encryption_manager._decrypt(cipher)

        assert plaintext != cipher and plaintext == bytes_block
    
    def test_verify_signature(self, ten_blocks: list[bytes], initialized_encryption_manager: EncryptionManager):
        # open a temp file to do this
        with tempfile.NamedTemporaryFile() as buffer:
            # write all blocks to the file
            for block in ten_blocks:
                initialized_encryption_manager._write_data_to_file(block, buffer) # type: ignore
            # hmac should be up to date; write it to file
            signature = initialized_encryption_manager.hmac.finalize()
            buffer.write(signature)

            # now reset buffer and the hmac
            buffer.seek(0)
            initialized_encryption_manager._reset_hmac()

            # and verify signature
            initialized_encryption_manager._verify_signature(buffer, signature) # type: ignore


    def test_get_hmac_from_file(self, encryption_manager: EncryptionManager, filled_buffer: BytesIO, bytes_block: bytes):
        # just make sure it gets last 32 bytes
        assert encryption_manager._get_hmac_from_file(filled_buffer) == bytes_block[-32:] # type: ignore

    def test_read_and_write_data_to_file(self, bytes_block: bytes, initialized_encryption_manager: EncryptionManager):
        # test that _write_data_to_file and _read_next_data_block work together
        in_memory_file = BytesIO()
        initialized_encryption_manager._write_data_to_file(bytes_block, in_memory_file) # type: ignore

        # reset pointer
        in_memory_file.seek(0)
        read_bytes = initialized_encryption_manager._read_next_data_block(in_memory_file) # type: ignore

        assert bytes_block == read_bytes

    def test_derive_key_from_password(self, encryption_manager: EncryptionManager, password: str):
        key1, salt1 = encryption_manager._derive_key_from_password(password)
        key2, salt2 = encryption_manager._derive_key_from_password(password, salt1)

        assert key1 == key2
        assert salt1 == salt2

        kdf = PBKDF2HMAC(
             algorithm=hashes.SHA256(),
             length=32,
             salt=salt1,
             iterations=390000,
        )
        kdf.verify(password.encode(), key1)
        