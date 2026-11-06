# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

PASSWORD = "cli integration passphrase"
ROOT = Path(__file__).resolve().parents[1]


def unprotect(path: Path) -> None:
    if not path.exists():
        return
    if sys.platform == "darwin":
        subprocess.run(["chflags", "nouchg", str(path)], check=False)
    elif sys.platform.startswith("linux"):
        subprocess.run(
            ["chattr", "-i", str(path)],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )


@pytest.fixture(autouse=True)
def _cleanup_immutable_files(tmp_path):
    yield
    for path in sorted(tmp_path.rglob("*"), reverse=True):
        unprotect(path)
    unprotect(tmp_path)


def run_cli(*args: str, password: str | None = None, check: bool = True):
    command = [sys.executable, "-m", "sandbox_cli.main", *args]
    result = subprocess.run(
        command,
        cwd=ROOT,
        input=(password + "\n") if password is not None else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if check and result.returncode != 0:
        raise AssertionError(
            f"command failed ({result.returncode}): {' '.join(command)}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result


def test_cli_end_to_end(tmp_path: Path):
    vault = tmp_path / "cli.sbx"
    source = tmp_path / "source"
    source.mkdir()
    (source / "hello.txt").write_text("hello from cli\n", encoding="utf-8")

    result = run_cli(
        "--password-stdin",
        "init",
        str(vault),
        "--memory-mib",
        "8",
        "--iterations",
        "1",
        password=PASSWORD,
    )
    assert "Created vault" in result.stdout
    assert "immutable" in result.stdout or "NOT protected" in result.stdout

    result = run_cli(
        "--password-stdin",
        "add",
        str(vault),
        str(source),
        password=PASSWORD,
    )
    assert "Added" in result.stdout

    result = run_cli(
        "--password-stdin", "list", str(vault), "--json", password=PASSWORD
    )
    assert "source/hello.txt" in result.stdout

    result = run_cli(
        "--password-stdin", "cat", str(vault), "source/hello.txt", password=PASSWORD
    )
    assert result.stdout == "hello from cli\n"

    out = tmp_path / "restored.txt"
    result = run_cli(
        "--password-stdin",
        "extract",
        str(vault),
        "source/hello.txt",
        "-o",
        str(out),
        password=PASSWORD,
    )
    assert "Extracted" in result.stdout
    assert out.read_text(encoding="utf-8") == "hello from cli\n"

    result = run_cli("info", str(vault))
    assert "Argon2id" in result.stdout
    assert "Deletion protection" in result.stdout

    result = run_cli(
        "--password-stdin", "verify", str(vault), password=PASSWORD
    )
    assert "Vault is intact" in result.stdout

    result = run_cli(
        "--password-stdin", "protect", str(vault)
    )
    assert "Deletion protection" in result.stdout

    bad = run_cli(
        "--password-stdin", "list", str(vault), password="not the password", check=False
    )
    assert bad.returncode != 0
    assert "wrong password" in bad.stderr.lower()


def test_cli_does_not_have_a_delete_command():
    result = run_cli("delete", check=False)
    assert result.returncode != 0
    assert "no such command" in result.stderr.lower()


def test_cli_short_password_is_rejected(tmp_path: Path):
    vault = tmp_path / "short.sbx"
    result = run_cli(
        "--password-stdin",
        "init",
        str(vault),
        "--memory-mib",
        "8",
        "--iterations",
        "1",
        password="short",
        check=False,
    )
    assert result.returncode != 0
    assert "at least 8 bytes" in result.stderr
    assert not vault.exists()


def test_cli_refuses_missing_vault(tmp_path: Path):
    result = run_cli(
        "--password-stdin",
        "list",
        str(tmp_path / "missing.sbx"),
        password=PASSWORD,
        check=False,
    )
    assert result.returncode != 0
    assert "does not exist" in result.stderr
