from gift.secrets.secrets_manager import SecretsManager
from gift.utils import shell_execute, log_shell_output
import json

class OnePasswordException(Exception):
    pass

def success(code: int) -> bool:
    return code == 0

class OnePasswordSecretsManager(SecretsManager):
    def __init__(self, vault: str, command: str) -> None:
        self.VAULT = vault
        self.OP_COMMAND = command
        
    def create_secret(self, indentifer: str, pwd_length: int) -> str:
        stdout, stderr, exit_code = shell_execute(
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
        if success(exit_code):
            try:
                return json.loads(stdout)["id"]
            except (json.JSONDecodeError, KeyError) as e:
                # continue to below error condition
                pass

        print("Error! Output from 1Password:")
        log_shell_output(stdout, stderr)
        raise OnePasswordException()


    def read_secret(self, indentifer: str) -> str:
        stdout, stderr, exit_code = shell_execute(
            self.OP_COMMAND,
            [   
                "read",
                f"op://{self.VAULT}/{indentifer}/password"
            ]
        )
        if stdout and success(exit_code): 
            return stdout
        else:
            print("Error! Output from 1Password:")
            log_shell_output(stdout, stderr)
            raise OnePasswordException()

    def delete_secret(self, identifier: str) -> None:
        stdout, stderr, exit_code = shell_execute(
            self.OP_COMMAND,
            [   
                "item",
                "delete",
                identifier
            ]
        )
        if not success(exit_code): 
            print("Error! Output from 1Password:")
            log_shell_output(stdout, stderr)
            raise OnePasswordException()

    def add_signature(self, indentifier: str, signature: str) -> str:
        stdout, stderr, exit_code = shell_execute(
            self.OP_COMMAND,
            [   
                "item",
                "edit",
                indentifier,
                f"Integrity.HMAC[password]={signature}",
                "--format=json"
            ]
        )
        if success(exit_code):
            try:
                return json.loads(stdout)["id"]
            except (json.JSONDecodeError, KeyError) as e:
                # continue to below error condition
                pass

        print("Error! Output from 1Password:")
        log_shell_output(stdout, stderr)
        raise OnePasswordException()
  
    def read_signature(self, indentifier: str) -> str:
        stdout, stderr, exit_code = shell_execute(
            self.OP_COMMAND,
            [   
                "item",
                "get",
                indentifier,
                "--fields",
                "label=Integrity.HMAC",
            ]
        )
        if stdout and success(exit_code): 
            return stdout
        else:
            print("Error! Output from 1Password:")
            log_shell_output(stdout, stderr)
            raise OnePasswordException()
        

        

