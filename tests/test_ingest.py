"""Ingest (scanner/ingest.py): list files, unpack uploads safely, validate git URLs.
Nothing here ever runs the scanned code."""

import stat
import zipfile

import pytest

from scanner.ingest import IngestError, Project, remove_tree, repo_name, safe_unzip, validate_git_url


def test_lists_relative_posix_paths_and_skips_tool_folders(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("print('hi')")
    (tmp_path / "README.md").write_text("# demo")
    for folder in (".git", "node_modules", "__pycache__", ".venv"):
        (tmp_path / folder).mkdir()
        (tmp_path / folder / "ignored.py").write_text("")
    project = Project.from_folder(tmp_path, max_files=100)
    assert project.files == ["README.md", "src/app.py"]
    assert project.name == tmp_path.name


def test_missing_folder_is_an_error(tmp_path):
    with pytest.raises(IngestError, match="not a folder"):
        Project.from_folder(tmp_path / "missing", max_files=100)


def test_too_many_files_is_an_error(tmp_path):
    for i in range(3):
        (tmp_path / f"f{i}.txt").write_text("x")
    with pytest.raises(IngestError, match="MAX_FILES"):
        Project.from_folder(tmp_path, max_files=2)


def test_read_text_survives_undecodable_bytes(tmp_path):
    (tmp_path / "data.bin").write_bytes(b"ok \xff\xfe")
    assert Project.from_folder(tmp_path, max_files=10).read_text("data.bin").startswith("ok ")


# --- safe unzip -----------------------------------------------------------------------------

def make_zip(path, entries):
    """entries: {name: bytes}, or {name: ("symlink", target)} for a symlink entry."""
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            if isinstance(data, tuple):
                info = zipfile.ZipInfo(name)
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
                zf.writestr(info, data[1])
            else:
                zf.writestr(name, data)
    return path


def test_safe_unzip_extracts_normal_files(tmp_path):
    archive = make_zip(tmp_path / "a.zip", {"app/main.py": b"print(1)", "app/static/": b""})
    safe_unzip(archive, tmp_path / "out", max_bytes=1 << 20, max_files=10)
    assert (tmp_path / "out" / "app" / "main.py").read_bytes() == b"print(1)"


@pytest.mark.parametrize("name", ["../evil.py", "app/../../evil.py", "/etc/cron.d/x", "C:/Windows/evil.dll"])
def test_zip_slip_is_refused(tmp_path, name):
    archive = make_zip(tmp_path / "a.zip", {name: b"x"})
    with pytest.raises(IngestError, match="unsafe path"):
        safe_unzip(archive, tmp_path / "out", max_bytes=1 << 20, max_files=10)
    assert not (tmp_path / "evil.py").exists()


def test_symlinks_are_skipped(tmp_path):
    archive = make_zip(tmp_path / "a.zip", {"link": ("symlink", "/etc/passwd"), "ok.txt": b"x"})
    safe_unzip(archive, tmp_path / "out", max_bytes=1 << 20, max_files=10)
    assert sorted(p.name for p in (tmp_path / "out").iterdir()) == ["ok.txt"]


def test_zip_bomb_and_too_many_files(tmp_path):
    bomb = make_zip(tmp_path / "bomb.zip", {"zeros.bin": bytes(3 << 20)})  # compresses to a few KB
    assert bomb.stat().st_size < 50_000
    with pytest.raises(IngestError, match="more than 1 MB"):
        safe_unzip(bomb, tmp_path / "out", max_bytes=1 << 20, max_files=10)
    many = make_zip(tmp_path / "many.zip", {f"f{i}.txt": b"x" for i in range(5)})
    with pytest.raises(IngestError, match="more than 3 files"):
        safe_unzip(many, tmp_path / "out2", max_bytes=1 << 20, max_files=3)


def test_remove_tree_deletes_read_only_files(tmp_path):
    """git pack files are read-only; plain rmtree(ignore_errors=True) leaves them on Windows."""
    pack = tmp_path / "scan" / ".git" / "objects" / "pack" / "pack-1.pack"
    pack.parent.mkdir(parents=True)
    pack.write_bytes(b"x")
    pack.chmod(stat.S_IREAD)
    remove_tree(tmp_path / "scan")
    assert not (tmp_path / "scan").exists()
    remove_tree(tmp_path / "missing")  # no error for a folder that is already gone


def test_not_a_zip(tmp_path):
    (tmp_path / "fake.zip").write_text("hello")
    with pytest.raises(IngestError, match="not a valid zip"):
        safe_unzip(tmp_path / "fake.zip", tmp_path / "out", max_bytes=1 << 20, max_files=10)


# --- git URLs ---------------------------------------------------------------------------------

HOSTS = ["github.com", "gitlab.com"]


@pytest.mark.parametrize(("url", "problem"), [
    ("file:///etc/passwd", "only https"),
    ("http://github.com/a/b", "only https"),
    ("git@github.com:a/b.git", "only https"),
    ("https://user:token@github.com/a/b", "credentials"),
    ("https://internal.example/a/b", "not allowed"),
    ("https://169.254.169.254/latest/meta-data", "not allowed"),
    ("https://github.com/only-owner", "expected a repository URL"),
    ("https://github.com/a/b?x=1", "expected a repository URL"),
])
def test_bad_git_urls_are_refused(url, problem):
    with pytest.raises(IngestError, match=problem):
        validate_git_url(url, HOSTS)


def test_good_git_url_and_repo_name():
    url = validate_git_url("  https://github.com/juice-shop/juice-shop.git ", HOSTS)
    assert repo_name(url) == "juice-shop"
