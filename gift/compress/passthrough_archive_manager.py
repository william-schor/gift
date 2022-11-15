from abc import ABC, abstractmethod
from pathlib import Path
from gift.compress.archive_manager import ArchiveManager


class PassthroughArchiveManager(ArchiveManager):
    def wrap(self, filepath: str | Path, workspace_path: str | Path) -> Path:
        return Path(filepath)

    def unwrap(self, archive_path: str | Path, dest_path: str | Path) -> None:
        return None