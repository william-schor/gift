from gift.secrets.secrets_manager import SecretsManager
from gift.utils import shell_execute, log_shell_output
import json

class OnePasswordException(Exception):
    pass


class OnePasswordSecretsManager(SecretsManager):
    VAULT = "FileWrap" # this can eventually be a setting
    OP_COMMAND = "op" # this can be a setting later

    def create_secret(self, indentifer: str, pwd_length: int) -> str:
        stdout, stderr = shell_execute(
            self.OP_COMMAND,
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
        except (json.JSONDecodeError, KeyError) as e:
            print("Error! Output from 1Password:")
            log_shell_output(stdout, stderr)
            raise OnePasswordException(e)


    def read_secret(self, indentifer: str) -> str:
        stdout, stderr = shell_execute(
            self.OP_COMMAND,
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
            raise OnePasswordException()

    def add_signature(self, indentifier: str, signature: str):
        stdout, stderr = shell_execute(
            self.OP_COMMAND,
            [   
                "item",
                "edit",
                indentifier,
                f"Integrity.HMAC[password]={signature}",
                "--format=json"
            ]
        )
        try:
            return json.loads(stdout)["id"]
        except (json.JSONDecodeError, KeyError) as e:
            print("Error! Output from 1Password:")
            log_shell_output(stdout, stderr)
            raise OnePasswordException(e)
  
    def read_signature(self, indentifier: str) -> str:
        stdout, stderr = shell_execute(
            self.OP_COMMAND,
            [   
                "item",
                "get",
                indentifier,
                "--fields"
                "Integrity.HMAC",
            ]
        )
        if stdout: 
            return stdout
        else:
            print("Error! Output from 1Password:")
            log_shell_output(stdout, stderr)
            raise OnePasswordException()
        

        

