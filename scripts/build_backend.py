"""Build distributions from an explicit, symlink-free source snapshot."""

import os
import shutil
import stat
import tempfile
from pathlib import Path, PurePosixPath

SOURCE_FILES = (
    "pyproject.toml",
    "README.md",
    "LICENSE.md",
    "requirements.txt",
    "package-files.txt",
    "scripts/build_backend.py",
)


def regular_file(root, name):
    """Check every component before reading, including directory symlinks."""
    path = root
    for part in PurePosixPath(name).parts:
        path /= part
        if path.is_symlink():
            raise ValueError(f"Packaging refuses symlink: {name}")
    if not stat.S_ISREG(path.stat().st_mode):
        raise ValueError(f"Packaging requires a regular file: {name}")
    return path


def package_files(root):
    """Use the same reviewed allow-list with or without a Git checkout."""
    names = regular_file(root, "package-files.txt").read_text().splitlines()
    for name in names:
        path = PurePosixPath(name)
        if (
            not name.startswith("cashu/")
            or ".." in path.parts
            or "\\" in name
            or path.as_posix() != name
        ):
            raise ValueError(f"Invalid package path: {name!r}")
    if not names or len(names) != len(set(names)):
        raise ValueError("Package manifest must contain unique file paths")
    return names


def source_files(root):
    # Do not traverse links, including unlisted, broken and directory links.
    if (root / "cashu").is_symlink():
        raise ValueError("Packaging refuses symlink: cashu")
    for directory, directories, files in os.walk(root / "cashu", followlinks=False):
        for name in directories + files:
            path = Path(directory, name)
            if path.is_symlink():
                raise ValueError(f"Packaging refuses symlink: {path.relative_to(root)}")
    return {
        name: regular_file(root, name) for name in (*SOURCE_FILES, *package_files(root))
    }


def build_snapshot(hook, output_directory, config_settings, metadata_directory=None):
    import uv_build

    root = Path.cwd()
    output = str(Path(output_directory).resolve())
    metadata = str(Path(metadata_directory).resolve()) if metadata_directory else None
    sources = source_files(root)
    with tempfile.TemporaryDirectory(prefix="cashu-build-") as directory:
        snapshot = Path(directory)
        for name, source in sources.items():
            target = snapshot / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
        try:
            os.chdir(snapshot)
            if hook == "build_sdist":
                return uv_build.build_sdist(output, config_settings)
            return uv_build.build_wheel(output, config_settings, metadata)
        finally:
            os.chdir(root)


def build_sdist(sdist_directory, config_settings=None):
    return build_snapshot("build_sdist", sdist_directory, config_settings)


def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    return build_snapshot(
        "build_wheel", wheel_directory, config_settings, metadata_directory
    )


def build_editable(wheel_directory, config_settings=None, metadata_directory=None):
    import uv_build

    # Editable installs must refer to the checkout, not a temporary snapshot.
    source_files(Path.cwd())
    return uv_build.build_editable(wheel_directory, config_settings, metadata_directory)


def prepare_metadata_for_build_wheel(metadata_directory, config_settings=None):
    import uv_build

    source_files(Path.cwd())
    return uv_build.prepare_metadata_for_build_wheel(
        metadata_directory, config_settings
    )


prepare_metadata_for_build_editable = prepare_metadata_for_build_wheel
