# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Praxis Contributors
"""Regression tests for the release dependency preflight."""

import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tools.check_release_dependencies import check_limitador, main


class ReleaseDependencyTests(unittest.TestCase):
    def test_published_limitador_is_accepted(self):
        check_limitador(
            {
                "packages": [
                    {
                        "name": "limitador",
                        "version": "0.14.0",
                        "source": "registry+https://github.com/rust-lang/crates.io-index",
                    }
                ]
            }
        )

    def test_git_and_path_sources_are_rejected_even_at_a_released_version(self):
        for source in (
            "git+https://github.com/Kuadrant/limitador#commit",
            "registry+https://example.invalid/index",
            None,
        ):
            with self.subTest(source=source), self.assertRaisesRegex(ValueError, "release blocked"):
                check_limitador(
                    {
                        "packages": [
                            {
                                "name": "limitador",
                                "version": "0.14.0",
                                "source": source,
                            }
                        ]
                    }
                )

    def test_a_registry_copy_does_not_hide_an_unreleased_copy(self):
        with self.assertRaisesRegex(ValueError, "release blocked"):
            check_limitador(
                {
                    "packages": [
                        {
                            "name": "limitador",
                            "version": "0.14.0",
                            "source": "registry+https://github.com/rust-lang/crates.io-index",
                        },
                        {"name": "limitador", "version": "0.15.0-dev", "source": "git+upstream"},
                    ]
                }
            )

    def test_missing_limitador_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "missing from the dependency graph"):
            check_limitador({"packages": []})

    def test_metadata_failure_blocks_release(self):
        failure = subprocess.CalledProcessError(101, "cargo metadata", stderr="resolution failed\n")
        with patch("tools.check_release_dependencies.subprocess.run", side_effect=failure):
            with contextlib.redirect_stderr(io.StringIO()) as stderr:
                self.assertEqual(main(), 101)
        self.assertIn("resolution failed", stderr.getvalue())

    def test_release_entrypoints_stop_before_tagging_or_uploading(self):
        root = Path(__file__).resolve().parents[2]
        metadata = {
            "packages": [
                {
                    "name": "limitador",
                    "version": "0.15.0-dev",
                    "source": "git+upstream",
                }
            ]
        }
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            (workspace / "tools").mkdir()
            for name in ("check_release_dependencies.py", "publish.sh"):
                shutil.copy2(root / "tools" / name, workspace / "tools" / name)
            shutil.copy2(root / "Makefile", workspace / "Makefile")
            bin_dir = workspace / "bin"
            bin_dir.mkdir()
            cargo = bin_dir / "cargo"
            cargo.write_text(
                '#!/bin/sh\nif [ "$1" = metadata ]; then\n'
                "cat <<'METADATA'\n" + json.dumps(metadata) + "\nMETADATA\n"
                "else\ntouch unexpected-side-effect\nexit 99\nfi\n"
            )
            cargo.chmod(0o755)
            for command in ("git", "curl"):
                stub = bin_dir / command
                stub.write_text("#!/bin/sh\ntouch unexpected-side-effect\nexit 99\n")
                stub.chmod(0o755)
            environment = dict(os.environ, PATH=str(bin_dir) + os.pathsep + os.environ["PATH"])
            for command in (
                ["make", "release-dry"],
                ["make", "release", "VERSION=0.6.1"],
                ["make", "tag", "VERSION=0.6.1"],
                ["tools/publish.sh"],
            ):
                with self.subTest(command=command):
                    result = subprocess.run(
                        command,
                        cwd=workspace,
                        env=environment,
                        capture_output=True,
                        text=True,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("release blocked:", result.stderr)
                    self.assertFalse((workspace / "unexpected-side-effect").exists())
