"""Project.from_folder (scanner/ingest.py): list files, never run them."""

import pytest

from scanner.ingest import IngestError, Project


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
