import shutil
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from typing import ContextManager

from alive_progress import alive_bar  # type: ignore
from alive_progress.animations.bars import bar_factory # type: ignore

class InternalException(Exception):
    pass

def shell_execute(command: str, arguments: list[str]) -> tuple[str, str, int]:
    cmd = [command]
    cmd.extend(arguments)
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout, result.stderr, result.returncode

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
    bar = bar_factory('🎁')
    return alive_bar(bar=bar, monitor=None, stats=None, title=title, receipt=False)



@contextmanager
def tempdir():
    path = tempfile.mkdtemp()
    try:
        yield path
    finally:
        try:
            shutil.rmtree(path)
        except IOError:
            sys.stderr.write('Failed to clean up temp dir {}'.format(path))