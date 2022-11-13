"""
A secrets manager using a simple dict, for testing purposes.

This is only in memory so does not survive consecutive calls to the cli.

Only used for in-memory unit testing.
"""

import random
import string


class DictSecretsManager:
    secret_store: dict = {}

    def create_secret(self, indentifer: str, pwd_length: int) -> str:
        self.secret_store[indentifer] = {
            "password": ''.join(random.choices(string.ascii_uppercase + string.digits, k=pwd_length)),
            "signature": ""
        }
        return indentifer

    def read_secret(self, indentifer: str):
        return self.secret_store[indentifer]["password"]

    def add_signature(self, indentifier: str, signature: str):
        self.secret_store[indentifier]["signature"] = signature
  
    def read_signature(self, indentifier: str) -> str:
        return self.secret_store[indentifier]["signature"]