import argparse
import re
import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib


def get_nutshell_version():
    settings_path = Path("cashu/core/settings.py")
    try:
        content = settings_path.read_text()
    except FileNotFoundError:
        print(f"File not found: {settings_path}")
        sys.exit(1)

    match = re.search(r'VERSION = "(.*?)"', content)
    if match:
        return match.group(1)
    raise ValueError("Could not find VERSION in cashu/core/settings.py")


def get_pyproject_version():
    pyproject_path = Path("pyproject.toml")
    try:
        with open("pyproject.toml", "rb") as f:
            data = tomllib.load(f)

        version = data["project"]["version"]
        return version
    except FileNotFoundError:
        print(f"File not found: {pyproject_path}")
        sys.exit(1)
    except KeyError:
        print(f"version not found inside {pyproject_path}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Verify versions match the tag.")
    parser.add_argument(
        "tag_version", help="The version from the git tag (e.g. v0.1.0)"
    )
    args = parser.parse_args()

    tag_version = args.tag_version
    # Strip 'v' prefix if present in tag
    if tag_version.startswith("v"):
        tag_version = tag_version[1:]

    try:
        nutshell_version = get_nutshell_version()
        pyproject_version = get_pyproject_version()
    except ValueError as e:
        print(f"Error reading versions: {e}")
        sys.exit(1)

    print(f"Tag version input: {args.tag_version} -> {tag_version}")
    print(f"Nutshell version: {nutshell_version}")
    print(f"Pyproject version: {pyproject_version}")

    errors = []
    if tag_version != nutshell_version:
        errors.append(
            f"Tag version {tag_version} does not match Nutshell version {nutshell_version}"
        )
    if tag_version != pyproject_version:
        errors.append(
            f"Tag version {tag_version} does not match Pyproject version {pyproject_version}"
        )

    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        sys.exit(1)

    print("All versions match!")


if __name__ == "__main__":
    main()
