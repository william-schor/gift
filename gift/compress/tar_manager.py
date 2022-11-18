import tarfile
from pathlib import Path

from gift.compress.archive_manager import ArchiveManager
from gift.constants import WRAPPING_SUFFIX
from gift.utils import InternalException


class TarManager(ArchiveManager):
    def wrap(self, filepath: str | Path, workspace_path: str | Path) -> Path:
        workspace = Path(workspace_path)
        new_file = workspace / f"{filepath}{WRAPPING_SUFFIX}"

        with tarfile.open(new_file, 'w:gz') as archive:
            archive.add(filepath, recursive=True)
        
        return new_file


    def unwrap(self, archive_path: str | Path, dest_path: str | Path) -> None:
        dest = Path(dest_path)
        if dest.exists() and not dest.is_dir():
            print(f"{dest_path} is not a directory! Please give a directory to unwrap into.")
            raise InternalException()

        with tarfile.open(archive_path, 'r:gz') as archive:
            archive.extractall(dest)
