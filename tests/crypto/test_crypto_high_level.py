from io import BytesIO
import os
from pathlib import Path
import tempfile

import pytest

from gift.crypto.encryption_manager import EncryptionManager
from gift.secrets.dict_secrets_manager import DictSecretsManager

TEST_BLOCK_SIZE = 512

class TestEncryptionManagerHighLevel:
    """
    These tests are for the high leve functions of the EncryptionManager:
        - .wrap()
        - .unwrap()
    """
    @pytest.mark.parametrize(
        "initial_data",
        [
            b'',
            os.urandom(TEST_BLOCK_SIZE),
            b''.join([os.urandom(TEST_BLOCK_SIZE) for _ in range(10)]),
            b''.join([os.urandom(TEST_BLOCK_SIZE) for _ in range(100)])
        ],
        ids=("empty file", "one block", "10 blocks", "100 blocks"),
    )
    def test_full_flow(self, initial_data: bytes):
        sm = DictSecretsManager()
        em = EncryptionManager(sm, TEST_BLOCK_SIZE) # type: ignore

        with (
            tempfile.NamedTemporaryFile(buffering=0) as source, 
            tempfile.NamedTemporaryFile(buffering=0) as wrapped, 
            tempfile.NamedTemporaryFile(buffering=0) as unwrapped
            ):
            source.write(initial_data)
            source.seek(0)
            
            # now wrap the source
            em.wrap(source, wrapped, source.name) # type: ignore

            # now lets examine the sink from the top
            wrapped.seek(0)

            salt = em._read_next_data_block(wrapped) # type: ignore
            password_id = em._read_next_data_block(wrapped) # type: ignore
            
            assert salt == em.salt
            assert em._bytes_to_str(password_id) in sm.secret_store

            # back to top and unwrap
            wrapped.seek(0)
            em.unwrap(wrapped, unwrapped) # type: ignore
            
            unwrapped.seek(0)
            result = unwrapped.read()

            assert result == initial_data

            
            
               