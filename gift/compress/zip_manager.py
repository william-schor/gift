from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile
from gift.compress.archive_manager import ArchiveManager

from gift.constants import WRAPPING_SUFFIX
from gift.utils import InternalException


class ZipManager(ArchiveManager):
    def wrap(self, filepath: str | Path, workspace_path: str | Path) -> Path:
        file = Path(filepath)
        workspace = Path(workspace_path)

        new_file = workspace / f"{filepath}{WRAPPING_SUFFIX}"

        if file.is_dir():
            with ZipFile(new_file, "w", ZIP_DEFLATED) as zip_file:
                    for entry in file.rglob("*"):
                        zip_file.write(entry, entry.relative_to(file))

        elif file.is_file():
            with ZipFile(new_file, "w", ZIP_DEFLATED) as zip_file:
                zip_file.write(file)
        else:
            print(f"We do not know what type of file {filepath} is!")
            raise InternalException()
        
        return new_file


    def unwrap(self, archive_path: str | Path, dest_path: str | Path) -> None:
        dest = Path(dest_path)
        if dest.exists() and not dest.is_dir():
            print(f"{dest_path} is not a directory! Please give a directory to unwrap into.")
            raise InternalException()
        with ZipFile(archive_path, "r") as zip_file:
            zip_file.extractall(dest)
