"""Ingest: turn what the user gave us into a local folder of files to scan.

The scanner only READS files. Nothing here (or anywhere in the engine) imports or runs
the scanned code.

Done (hours 0-4):  Project.from_folder() - list the files of a local folder.
Next (hours 4-14): safe unzip (reject absolute paths and '..', skip symlinks, cap total
                   size at MAX_UPLOAD_MB and file count at MAX_FILES), git clone into a
                   temp folder, file classification (code / schema / config / frontend),
                   temp folder deleted in try/finally.
"""

import os
from dataclasses import dataclass
from pathlib import Path

from scanner.config import get_settings

# Folders holding tool caches or third-party code rather than the project's own code.
SKIP_DIRS = frozenset({
    ".git", ".hg", ".svn", ".venv", "venv", "node_modules", "__pycache__",
    ".pytest_cache", ".mypy_cache", ".tox", "dist", "build",
})


class IngestError(Exception):
    """The input cannot be scanned (missing folder, too many files, ...)."""


@dataclass
class Project:
    """A folder ready to scan. `files` are sorted POSIX paths relative to `root`."""

    root: Path
    files: list[str]

    @property
    def name(self) -> str:
        return self.root.name

    def read_text(self, rel_path: str) -> str:
        """Read a file as text. Undecodable bytes become U+FFFD instead of crashing the scan."""
        return (self.root / rel_path).read_text(encoding="utf-8", errors="replace")

    @classmethod
    def from_folder(cls, folder: Path | str, max_files: int | None = None) -> "Project":
        limit = max_files if max_files is not None else get_settings().max_files
        root = Path(folder).resolve()
        if not root.is_dir():
            raise IngestError(f"not a folder: {folder}")
        files: list[str] = []
        for dirpath, dirnames, filenames in os.walk(root):  # does not follow symlinked folders
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for name in filenames:
                path = Path(dirpath) / name
                if path.is_symlink():
                    continue
                files.append(path.relative_to(root).as_posix())
                if len(files) > limit:
                    raise IngestError(f"more than {limit} files; raise MAX_FILES to scan this project")
        return cls(root=root, files=sorted(files))
