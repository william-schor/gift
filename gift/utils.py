import click
import shutil
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from typing import ContextManager, Generator

from alive_progress import alive_bar  # type: ignore
from alive_progress.animations.bars import bar_factory  # type: ignore


class InternalException(Exception):
    pass

def shell_execute(command: str, arguments: list[str]) -> tuple[str, str, int]:
    cmd = [command]
    cmd.extend(arguments)
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout, result.stderr, result.returncode

def log_shell_output(stdout: str, stderr: str) -> None:
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
def tempdir() -> Generator:
    path = tempfile.mkdtemp()
    try:
        yield path
    finally:
        try:
            shutil.rmtree(path)
        except IOError:
            sys.stderr.write('Failed to clean up temp dir {}'.format(path))


class colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def warn(warning: str) -> None:
    click.echo(f"{colors.WARNING}{warning}{colors.ENDC}")

