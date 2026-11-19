# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Praxis Contributors
"""Refuse releases that resolve Limitador outside crates.io."""

import json
from pathlib import Path
import subprocess
import sys


def check_limitador(metadata: dict) -> None:
    packages = [package for package in metadata["packages"] if package["name"] == "limitador"]
    if not packages:
        raise ValueError("release blocked: Limitador is missing from the dependency graph")

    for package in packages:
        source = package.get("source")
        if source != "registry+https://github.com/rust-lang/crates.io-index":
            raise ValueError(
                f"release blocked: Limitador {package['version']} resolves from {source or 'a local path'}; "
                "use a published crates.io dependency before releasing"
            )


def main() -> int:
    try:
        result = subprocess.run(
            [
                "cargo",
                "metadata",
                "--locked",
                "--format-version",
                "1",
                "--features",
                "praxis-policy-builtins/experimental-ratelimit",
            ],
            cwd=Path(__file__).resolve().parent.parent,
            capture_output=True,
            check=True,
            text=True,
        )
        check_limitador(json.loads(result.stdout))
    except subprocess.CalledProcessError as error:
        print(error.stderr, file=sys.stderr, end="")
        return error.returncode
    except (OSError, ValueError) as error:
        print(error, file=sys.stderr)
        return 1

    print("release dependencies: Limitador resolves from crates.io")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
