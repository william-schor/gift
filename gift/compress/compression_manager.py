from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

from alive_progress import alive_bar # type: ignore
from gift.constants import INTER_SUFFIX 

from gift.utils import InternalException


class CompressionManager:
    def wrap(self, filepath: str):
        file = Path(filepath)
        if file.is_dir():
            with ZipFile(f"{file.stem}{INTER_SUFFIX}", "w", ZIP_DEFLATED) as zip_file:
                with alive_bar(dual_line=True, title='Compressing', ctrl_c=False) as bar:
                    for entry in file.rglob("*"):
                        if entry.is_dir():
                            print(f"Entering directory {entry}")
                        bar.text = f"-> Adding file: {entry}, please wait..."
                        zip_file.write(entry, entry.relative_to(file))
                        bar()

        elif file.is_file():
            with ZipFile(f"{file.stem}{INTER_SUFFIX}", "w", ZIP_DEFLATED) as zip_file:
                zip_file.write(entry)
        else:
            print(f"We do not know what type of file {filepath} is!")
            raise InternalException()


    def unwrap(self, archive_path: str, dest_path: str):
        dest = Path(dest_path)
        if dest.exists() and not dest.is_dir():
            print(f"{dest_path} is not a directory! Please give a directory to unwrap into.")
            raise InternalException()
        with ZipFile(archive_path, "r") as zip_file:
            zip_file.extractall(dest / f"{archive_path.removesuffix(INTER_SUFFIX)}")
