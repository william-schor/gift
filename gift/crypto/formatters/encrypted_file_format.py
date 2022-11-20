"""
File formatters define the format of the file, 
on top of the crypto engines, which supplies the 
underlying crypto primitives.
"""
import struct
from io import BufferedReader, BufferedWriter
from pathlib import Path

from gift.crypto.encryption_engine_builder import EncryptionEngineBuilder

"""
File Format:

----------------------------
    len(key_components)     |
    key_components[0]       |
    key_components[1]       |
            .               |
            .               |
            .               |
    key_components[-1]      |
    data blocks             |
            .               |
            .               |
            .               |
----------------------------
    HMAC      (N bytes)     |
----------------------------

Note that all sections (except the HMAC for security reasons) are prefixed
with their own length (4 bytes) to allow easy deserialization.
"""

class IntegrityViolation(Exception):
    pass

class EncyptedFileFormatV1:
    def __init__(
        self, 
        encryption_engine_builder: EncryptionEngineBuilder,
        block_size: int
    ) -> None:
        self.encryption_engine_builder = encryption_engine_builder
        self.block_size = block_size
        

    def wrap(self, filename: str, source: BufferedReader, sink: BufferedWriter) -> str | None:
        # build an encryption engine
        self.encryption_engine = self.encryption_engine_builder.build_wrapper(secret_name=filename)

        # first, get all key components
        key_components_to_save = self.encryption_engine.get_public_key_components()

        # then, save the number of components 
        number_of_key_components = len(key_components_to_save)
        self.__write_data_to_file(struct.pack('<I', number_of_key_components), sink)

        # and the components themselves
        for key_component in key_components_to_save:
            self.__write_data_to_file(key_component, sink)  
 

        # now write the file, encrypted in chunks (secret)
        while True:
            chunk = source.read(self.block_size)
            if len(chunk) == 0:
                break
            
            enc = self.encryption_engine.encrypt(chunk)
            self.__write_data_to_file(enc, sink)

            if len(chunk) < self.block_size:
                break
            
        # Note: The encryption engine takes care of adding the signature
        # to the end of the file itself to discourage any implementation from
        # changing the pattern of the signature being the last N bytes,
        # which could result in security flaws.
        # "N" should be known the the decryption algorithm from a trusted source 
        # (i.e. the source code or a user setting). 
        self.encryption_engine.sign(sink)

        return self.encryption_engine.get_secret_id().decode()



    def unwrap(self, source: BufferedReader, sink: BufferedWriter) -> str | None:  
        # start by reading UNVERIFIED data 
        ## get key components      
        number_of_key_components_bytes = self.__read_next_data_block(source)
        number_of_key_components: int = struct.unpack('<I', number_of_key_components_bytes)[0]

        ## then the components themselves
        key_components = [
            self.__read_next_data_block(source) for _ in range(number_of_key_components)
        ]
        # build an encryption engine
        self.encryption_engine = self.encryption_engine_builder.build_unwrapper(key_components)

        # verify the signature (may raise IntegrityViolation)
        self.encryption_engine.verify_signature(source, self.block_size)

        # Now we can decrypt the file
        ## source is pointing to the start of data blocks
        ## Figure out how far to read
        end_of_data = Path(source.name).stat().st_size - self.encryption_engine.SIGNATURE_LENGTH

        ## read, decrypt, and write out the chunks
        while source.tell() < end_of_data:
            encrypted_chunk = self.__read_next_data_block(source)
            chunk = self.encryption_engine.decrypt(encrypted_chunk)
            sink.write(chunk)
        
        return self.encryption_engine.get_secret_id().decode()


    def __write_data_to_file(self, data: bytes, sink: BufferedWriter) -> None:
        # enrich with length
        full_block = struct.pack('<I', len(data)) + data

        # update hmac
        self.encryption_engine.update_signature(full_block)

        # write to file
        sink.write(full_block)
    
    def __read_next_data_block(self, source: BufferedReader) -> bytes:
        size_bytes = source.read(4)
        size: int = struct.unpack('<I', size_bytes)[0]
        
        return source.read(size)
    