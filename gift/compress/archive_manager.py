from abc import ABC, abstractmethod
from pathlib import Path


class ArchiveManager(ABC):
    @abstractmethod
    def wrap(self, filepath: str | Path, workspace_path: str | Path) -> Path:
        pass

    @abstractmethod
    def unwrap(self, archive_path: str | Path, dest_path: str | Path) -> None:
        pass