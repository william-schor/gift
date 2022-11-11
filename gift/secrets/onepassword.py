from typing import NoReturn
from gift.secrets.secrets_manager import SecretsManager
from string import Template
from gift.utils import InternalException, shell_execute, log_shell_output
import json


class OnePasswordSecretsManager(SecretsManager):
    write_cmd: Template = Template("op item create \
        --category=password \
        --title=$title \
        --vault=$vault \
        --generate-password=$length,letters,digits \
        --format=json"
    )
    DEFAULT_VAULT = "FileWrap"

    def get_secret(self, indentifer: str) -> str:
        stdout, stderr = shell_execute(
            "op",
            [
                "read",
                f"op://FileWrap/{indentifer}/password"
            ]
        )
        if stdout: 
            return stdout
        else:
            print("Error! Output from 1Password:")
            log_shell_output(stdout, stderr)
            raise InternalException


    def create_secret(self, indentifer: str, pwd_length, **kwargs) -> str:
        if "vault" not in kwargs:
            print(f"defaulting to 1Password Vault {self.DEFAULT_VAULT}")
            vault = self.DEFAULT_VAULT
        else:
            vault = kwargs["vault"]

        stdout, stderr = shell_execute(
            "op",
            [
                "item",
                "create",
                "--category=password",
                f"--title={indentifer}",
                f"--vault={vault}",
                f"--generate-password={pwd_length},letters,digits",
                f"--format=json"
            ]
        )
        try:
            return json.loads(stdout)["id"]
        except json.JSONDecodeError:
            print("Error! Output from 1Password:")
            log_shell_output(stdout, stderr)
            raise InternalException

        

