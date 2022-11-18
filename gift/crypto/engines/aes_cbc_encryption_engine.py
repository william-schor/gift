import base64
import os
from io import SEEK_SET, BufferedReader, BufferedWriter
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from gift.secrets.secrets_manager import SecretsManager
from gift.crypto.engines.encryption_engine import EncryptionEngine

class IntegrityViolation(Exception):
    pass

class AesCbcEncryptionEngine(EncryptionEngine):
    def __init__(
        self, 
        secret_manager: SecretsManager, 
        salt: bytes | None = None, 
        secret_id: str | None = None,
        secret_name: str | None = None,
        secret_length: int = 30
    ) -> None:

        self.secret_manager = secret_manager
        self.SIGNATURE_LENGTH = 32
        self.salt = salt if salt else os.urandom(16)

        if secret_id:
            self.secret_id = secret_id 
        elif secret_name:
            self.secret_id = self.secret_manager.create_secret(secret_name, secret_length)
        else:
            raise ValueError("Either secret_id or secret_name must be defined!")

        secret = self.secret_manager.read_secret(self.secret_id)
        key = self.__derive_key_from_secret(secret, self.salt)

        self.encryption_key = key[:16]
        self.signing_key = key[16:]
        self.hmac = HMAC(self.signing_key, hashes.SHA256())

    def get_public_key_components(self) -> list[bytes]:
        return [self.salt, self.secret_id.encode()]

    def get_secret_id(self) -> bytes:
        return self.secret_id.encode()

    def encrypt(self, chunk: bytes) -> bytes:
        # generate iv
        iv = os.urandom(16)

        # pad
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(chunk) + padder.finalize()

        # encrypt
        encryptor = Cipher(
            algorithms.AES(self.encryption_key),
            modes.CBC(iv),
        ).encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        return iv + ciphertext

    def decrypt(self, chunk: bytes) -> bytes:
        # find iv
        iv = chunk[:16]
        ciphertext = chunk[16:]

        # decrypt
        decryptor = Cipher(
            algorithms.AES(self.encryption_key), modes.CBC(iv)
        ).decryptor()
        plaintext_padded = decryptor.update(ciphertext)
        plaintext_padded += decryptor.finalize()

        # unpad
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        unpadded = unpadder.update(plaintext_padded)
        unpadded += unpadder.finalize()

        return unpadded

    def update_signature(self, full_block: bytes) -> None:
        self.hmac.update(full_block)

    def sign(self, sink: BufferedWriter) -> None:
        # assume all the data in the file is in the HMAC. 
        # Add the HMAC to the end of the file.
        final_signature = self.hmac.finalize()
        sink.write(final_signature)

        # Additionally save the HMAC to the SecretManager
        self.secret_manager.add_signature(
            self.secret_id, 
            self._bytes_to_b64(final_signature)
        )
        # HMAC is now finalized and update_signature will raie an Exception

    def verify_signature(self, source: BufferedReader, block_size: int) -> None:
        # save current position in file to return to at the end
        incoming_fp_position = source.tell()
        # start at the beginning of the file
        source.seek(0, SEEK_SET)
        
        source_file_size = Path(source.name).stat().st_size
        bytes_left_to_be_read = source_file_size - self.SIGNATURE_LENGTH

        while True:
            if bytes_left_to_be_read > block_size:
                # there is at least block_size left; read it
                chunk = source.read(block_size)
                # update the hmac
                self.hmac.update(chunk)
                # record the read
                bytes_left_to_be_read -= block_size
            else:
                # only some bytes remain; read those
                chunk = source.read(bytes_left_to_be_read)
                # update the hmac
                self.hmac.update(chunk)
                # now we are done
                break
        
        signature = source.read(self.SIGNATURE_LENGTH)
        try: 
            self.hmac.verify(signature)
        except InvalidSignature:
            raise IntegrityViolation("Signature verification failed!")

        # if all goes well, return the file pointer to where it started
        source.seek(incoming_fp_position, SEEK_SET)

        
    def __derive_key_from_secret(self, password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=390000,
        )
        key = kdf.derive(password.encode())
        return key
    
    def _b64_to_bytes(self, s: str) -> bytes:
        return base64.b64decode(s)
        
    def _bytes_to_b64(self, b: bytes) -> str:
        return base64.b64encode(b).decode()