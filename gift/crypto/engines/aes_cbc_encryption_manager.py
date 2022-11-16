import base64
import os
import struct
from io import SEEK_END, SEEK_SET, BufferedReader, BufferedWriter
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from gift.constants import BLOCK_SIZE, FINAL_SUFFIX
from gift.secrets.secrets_manager import SecretsManager
from gift.crypto.engines.encryption_manager import EncryptionManager

"""
File format:

----------------------------
    salt  (16 bytes)        |
    password id             |
    data blocks             |
       .                    |
       .                    |
       .                    |
----------------------------
    HMAC     (32 bytes)     |
----------------------------
"""

class IntegrityViolation(Exception):
    pass

class AesCbcEncryptionManager(EncryptionManager):
    def __init__(
        self, 
        secret_manager: SecretsManager,
        block_size: int | None = None
    ) -> None:
        self.secret_manager = secret_manager
        if block_size:
            self.block_size = block_size
        else:
            self.block_size = BLOCK_SIZE
        
    def _init_key_material(self, password: str, salt_candidate: bytes | None = None) -> None:
        key, salt = self._derive_key_from_password(password, salt_candidate)

        self.encryption_key = key[:16]
        self.signing_key = key[16:]
        self.salt = salt # 16 bytes
        self.hmac = HMAC(self.signing_key, hashes.SHA256())


    def wrap(self, source: BufferedReader, sink: BufferedWriter, password_length: int =30) -> None:
        password_id = self.secret_manager.create_secret(
            sink.name.removesuffix(FINAL_SUFFIX),
            password_length
        )
        # as a precaution, always do a read to retrive the password we just wrote
        password = self.secret_manager.read_secret(password_id)

        # now build keys
        self._init_key_material(password)

        # write salt to file (not secret)
        self._write_data_to_file(self.salt, sink)  

        # write password id to file (not secret)
        self._write_data_to_file(
            password_id.encode(),
            sink
        )   

        # now write the file, encrypted in chunks (secret)
        while True:
            chunk = source.read(self.block_size)
            if len(chunk) == 0:
                break
            
            enc = self._encrypt(chunk)
            self._write_data_to_file(enc, sink)

            if len(chunk) < self.block_size:
                break
        
        # now, all the data in the file is in the HMAC. 
        # Add the HMAC to the end of the file.
        final_signature = self.hmac.finalize()
        sink.write(final_signature)

        # Additionally save the HMAC to the SecretManager
        self.secret_manager.add_signature(
            password_id, 
            self._bytes_to_b64(final_signature)
        )

        # reset HMAC (just in case)
        self._reset_hmac()

    def unwrap(self, source: BufferedReader, sink: BufferedWriter) -> str | None:  
        # start by reading UNVERIFIED data       
        salt = self._read_next_data_block(source)
        password_id = self._read_next_data_block(source).decode()

        # make sure the stored hash matches the file's hash
        stored_signature = self._b64_to_bytes(self.secret_manager.read_signature(password_id))
        file_signature = self._get_hmac_from_file(source)

        if stored_signature != file_signature:
            raise IntegrityViolation("hash in file does not match hash in SecretManager!")
        
        # if so, we can proceed to check if the contents match the HMAC
        password = self.secret_manager.read_secret(password_id)
        
        # build keys
        self._init_key_material(password, salt_candidate=salt)

        # verify signature (may raise IntegrityViolation)
        self._verify_signature(source, file_signature)

        # Now we can decrypt the file
        ## source is pointing to the start of data blocks
        ## Figure out how far to read
        end_of_data = Path(source.name).stat().st_size - 32

        ## read, decrypt, and write out the chunks
        while source.tell() < end_of_data:
            encrypted_chunk = self._read_next_data_block(source)
            chunk = self._decrypt(encrypted_chunk)
            sink.write(chunk)
        
        return password_id

    def _encrypt(self, data: bytes) -> bytes:
        # generate iv
        iv = os.urandom(16)

        # pad
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()


        # encrypt
        encryptor = Cipher(
            algorithms.AES(self.encryption_key),
            modes.CBC(iv),
        ).encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        return iv + ciphertext

    def _decrypt(self, token: bytes) -> bytes:
        # find iv
        iv = token[:16]
        ciphertext = token[16:]

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
    
    def _verify_signature(self, source: BufferedReader, signature: bytes) -> None:
        # save current position in file to return to at the end
        incoming_fp_position = source.tell()
        # start at the beginning of the file
        source.seek(0, SEEK_SET)
        
        source_file_size = Path(source.name).stat().st_size
        bytes_left_to_be_read = source_file_size - 32

        while True:
            if bytes_left_to_be_read > self.block_size:
                # there is at least self.block_size left; read it
                chunk = source.read(self.block_size)
                # update the hmac
                self.hmac.update(chunk)
                # record the read
                bytes_left_to_be_read -= self.block_size
            else:
                # only some bytes remain; read those
                chunk = source.read(bytes_left_to_be_read)
                # update the hmac
                self.hmac.update(chunk)
                # now we are done
                break

        # verify the hmac
        try: 
            self.hmac.verify(signature)
        except InvalidSignature:
            raise IntegrityViolation("Signature verification failed!")

        # if all goes well, return the file pointer to where it started
        source.seek(incoming_fp_position, SEEK_SET)


    def _get_hmac_from_file(self, source: BufferedReader) -> bytes:
        # save current position in file to return to at the end
        incoming_fp_position = source.tell()

        # grab signature from the end of the file
        source.seek(-32, SEEK_END)
        signature = source.read(32)
       
        # return the file pointer to where it started
        source.seek(incoming_fp_position, SEEK_SET)
        return signature

    def _write_data_to_file(self, data: bytes, sink: BufferedWriter) -> None:
        # enrich with length
        full_block = struct.pack('<I', len(data)) + data

        # update hmac
        self.hmac.update(full_block)

        # write to file
        sink.write(full_block)
    
    def _read_next_data_block(self, source: BufferedReader) -> bytes:
        size_bytes = source.read(4)
        size: int = struct.unpack('<I', size_bytes)[0]
        
        return source.read(size)
    
    def _derive_key_from_password(self, password: str, salt: bytes | None = None) -> tuple[bytes, bytes]:
        if salt is None:
            salt = os.urandom(16)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=390000,
        )
        key = kdf.derive(password.encode())
        return key, salt
    
    def _reset_hmac(self) -> None:
        self.hmac = HMAC(self.signing_key, hashes.SHA256())
    
    def _b64_to_bytes(self, s: str) -> bytes:
        return base64.b64decode(s)
        
    def _bytes_to_b64(self, b: bytes) -> str:
        return base64.b64encode(b).decode()