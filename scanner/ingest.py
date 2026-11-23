"""Ingest: turn what the user gave us into a local folder of files to scan.

The scanner only READS files. Nothing here (or anywhere in the engine) imports or runs
the scanned code.

- Project.from_folder(): list the files of a local folder (skips tool folders, symlinks)
- safe_unzip(): unpack an upload; rejects absolute paths and '..' (zip slip), skips
  symlinks, caps the unpacked size (MAX_UPLOAD_MB) and file count (MAX_FILES) - zip bombs
- validate_git_url() + clone_git(): https only, allowed hosts only (ALLOWED_GIT_HOSTS), no
  credentials in the URL; shallow clone with a timeout, symlinks checked out as plain files,
  never prompts for a password
The caller unpacks / clones into a temp folder and deletes it in try/finally
(backend/jobs.py). File kinds for the report: scanner/engine.py.
"""

import os
import shutil
import stat
import subprocess
import zipfile
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any
from urllib.parse import urlsplit

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
    # Work shared by detectors within one scan (parsed files, routes, tables), so each file
    # is parsed once instead of once per detector.
    cache: dict[str, Any] = field(default_factory=dict, repr=False, compare=False)

    @property
    def name(self) -> str:
        return self.root.name

    def cached(self, key: str, compute: Callable[[], Any]) -> Any:
        if key not in self.cache:
            self.cache[key] = compute()
        return self.cache[key]

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


def remove_tree(path: Path) -> None:
    """Delete a folder completely, including read-only files (git makes its pack files
    read-only, and on Windows plain shutil.rmtree(ignore_errors=True) silently leaves
    them behind). Uploaded code must never be kept."""

    def make_writable_and_retry(function, failed_path, _exc):
        os.chmod(failed_path, stat.S_IWRITE)
        function(failed_path)

    if Path(path).exists():
        shutil.rmtree(path, onexc=make_writable_and_retry)


# --- uploads: safe unzip ----------------------------------------------------------------

def safe_unzip(archive: Path, dest: Path, max_bytes: int, max_files: int) -> Path:
    """Unpack a zip upload into dest, refusing anything that could escape dest or exhaust
    the disk. Raises IngestError with a message that is safe to show to the uploader."""
    try:
        zf = zipfile.ZipFile(archive)
    except (zipfile.BadZipFile, OSError):
        raise IngestError("the upload is not a valid zip file") from None
    dest.mkdir(parents=True, exist_ok=True)
    root = dest.resolve()
    with zf:
        entries = zf.infolist()
        if sum(1 for e in entries if not e.is_dir()) > max_files:
            raise IngestError(f"the zip holds more than {max_files} files")
        written = 0
        for entry in entries:
            name = entry.filename.replace("\\", "/")
            parts = PurePosixPath(name).parts
            if name.startswith("/") or PureWindowsPath(name).drive or ".." in parts:
                raise IngestError(f"unsafe path in the zip: {entry.filename!r}")  # zip slip
            if stat.S_ISLNK(entry.external_attr >> 16):
                continue  # symlinks could point anywhere on the server: skip them
            target = (dest / name).resolve()
            if target != root and root not in target.parents:
                raise IngestError(f"unsafe path in the zip: {entry.filename!r}")
            if entry.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            try:
                with zf.open(entry) as src, open(target, "wb") as out:
                    while chunk := src.read(1 << 16):  # count real bytes: headers can lie
                        written += len(chunk)
                        if written > max_bytes:
                            raise IngestError(f"the zip unpacks to more than {max_bytes // (1 << 20)} MB")
                        out.write(chunk)
            except (RuntimeError, zipfile.BadZipFile, NotImplementedError) as exc:  # encrypted / corrupt
                raise IngestError(f"cannot unpack {entry.filename!r}: {exc}") from None
    return dest


# --- git URLs ---------------------------------------------------------------------------

def validate_git_url(url: str, allowed_hosts: list[str]) -> str:
    """Return the URL if it is an https URL on an allowed host, else raise IngestError."""
    url = (url or "").strip()
    parts = urlsplit(url)
    if parts.scheme != "https":
        raise IngestError("only https:// git URLs are accepted")
    if parts.username or parts.password:
        raise IngestError("remove credentials from the git URL; only public repositories can be scanned")
    if (parts.hostname or "").lower() not in {h.lower() for h in allowed_hosts}:
        raise IngestError(f"git host not allowed; allowed hosts: {', '.join(allowed_hosts)}")
    if len([p for p in parts.path.split("/") if p]) < 2 or parts.query or parts.fragment:
        raise IngestError("expected a repository URL like https://github.com/owner/repo")
    return url


def repo_name(url: str) -> str:
    """'https://github.com/juice-shop/juice-shop.git' -> 'juice-shop'."""
    name = [p for p in urlsplit(url).path.split("/") if p][-1]
    return name[:-4] if name.endswith(".git") else name


def clone_git(url: str, dest: Path, timeout: int, max_bytes: int) -> Path:
    """Shallow-clone a validated https URL into dest (never runs anything from the repo)."""
    git = shutil.which("git")
    if git is None:
        raise IngestError("git is not installed on the server")
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_LFS_SKIP_SMUDGE": "1", "GCM_INTERACTIVE": "never"}
    command = [git, "-c", "core.symlinks=false", "-c", "protocol.file.allow=never",
               "clone", "--depth", "1", "--single-branch", "--no-tags", "--", url, str(dest)]
    try:
        result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise IngestError(f"git clone took longer than {timeout} seconds") from None
    if result.returncode != 0:
        raise IngestError("git clone failed: is the repository public and the URL correct?")
    remove_tree(dest / ".git")  # history is not scanned; drop it now (its files are read-only)
    size = sum(p.stat().st_size for p in dest.rglob("*") if p.is_file() and ".git" not in p.parts)
    if size > max_bytes:
        raise IngestError(f"the repository is larger than {max_bytes // (1 << 20)} MB")
    return dest
