from gift.secrets.secrets_manager import SecretsManager
from gift.utils import InternalException, shell_execute, log_shell_output
import json


class OnePasswordSecretsManager(SecretsManager):
    VAULT = "FileWrap" # this can eventually be a setting

    def create_secret(self, indentifer: str, pwd_length: int) -> str:
        stdout, stderr = shell_execute(
            "op",
            [
                "item",
                "create",
                "--category=password",
                f"--title={indentifer}",
                f"--vault={self.VAULT}",
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


    def read_secret(self, indentifer: str) -> str:
        stdout, stderr = shell_execute(
            "op",
            [   
                "read",
                f"op://{self.VAULT}/{indentifer}/password"
            ]
        )
        if stdout: 
            return stdout
        else:
            print("Error! Output from 1Password:")
            log_shell_output(stdout, stderr)
            raise InternalException

    # def add_signature(self, indentifier: str, hash: str):
    #     pass
  
    # def get_signature(self, indentifier: str) -> str:
    #     pass

        

