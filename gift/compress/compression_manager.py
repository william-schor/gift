from pathlib import Path
from gift.utils import InternalException
from zipfile import ZipFile, ZIP_DEFLATED

SUFFIX = ".wrapped"

class CompressionManager:
    def compress(self, filepath: str):
        file = Path(filepath)
        if file.is_dir():
            with ZipFile(f"{file.stem}{SUFFIX}", "w", ZIP_DEFLATED) as zip_file:
                for entry in file.rglob("*"):
                    zip_file.write(entry, entry.relative_to(file))
        elif file.is_file():
            with ZipFile(f"{file.stem}{SUFFIX}", "w", ZIP_DEFLATED) as zip_file:
                zip_file.write(entry)
        else:
            print(f"We do not know what type of file {filepath} is!")
            raise InternalException()


    def open(self, archive_path: str, dest_path: str):
        dest = Path(dest_path)

        if dest.exists() and not dest.is_dir():
            print(f"{dest_path} is not a directory! Please give a directory to unwrap into.")
            raise InternalException()
        with ZipFile(archive_path, "r") as zip_file:
            zip_file.extractall(dest / f"{archive_path.removesuffix(SUFFIX)}")
