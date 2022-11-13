import subprocess
from typing import ContextManager
from alive_progress import alive_bar # type: ignore

class InternalException(Exception):
    pass

def shell_execute(command: str, arguments: list[str]) -> tuple[str, str]:
    cmd = [command]
    cmd.extend(arguments)
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout, result.stderr

def log_shell_output(stdout, stderr):
    if stdout:
        print(f'{"stdout":_^30}')
        print(stdout)
        print("_"*30)
    if stderr:
        print(f'{"stderr":_^30}')
        print(stderr)
        print("_"*30)



def spinner(title: str | None = None) -> ContextManager:
    return alive_bar(monitor=None, stats=None, title=title)
