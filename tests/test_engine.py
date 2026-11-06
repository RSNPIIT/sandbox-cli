# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from sandbox_cli import sandbox_engine as engine

PASSWORD = "correct horse battery staple"
MEMORY_MIB = 8
ITERATIONS = 1


def unprotect(path: Path) -> None:
    """Test cleanup only. The shipped CLI deliberately has no unlock command."""
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


def make_vault(tmp_path: Path, protect: bool = False) -> Path:
    vault = tmp_path / "vault.sbx"
    engine.create_vault(
        str(vault),
        PASSWORD,
        MEMORY_MIB,
        ITERATIONS,
        1,
        protect,
    )
    return vault


def test_create_add_list_cat_extract_verify(tmp_path: Path):
    vault = make_vault(tmp_path)
    source = tmp_path / "src"
    (source / "sub").mkdir(parents=True)
    (source / "empty").mkdir()
    (source / "a.txt").write_text("alpha\n", encoding="utf-8")
    (source / "sub" / "b.bin").write_bytes(b"beta\x00\xff")
    (source / "zero").write_bytes(b"")

    added = engine.add_paths(str(vault), PASSWORD, [str(source)], None, False)
    assert added.files_added == 3
    assert added.dirs_added == 3
    assert added.total_entries == 6
    assert added.skipped == []

    entries = engine.list_entries(str(vault), PASSWORD)
    paths = {entry.path for entry in entries}
    assert paths == {
        "src",
        "src/a.txt",
        "src/empty",
        "src/sub",
        "src/sub/b.bin",
        "src/zero",
    }

    binary = next(entry for entry in entries if entry.path == "src/sub/b.bin")
    assert binary.kind == "file"
    assert binary.size == 6
    assert binary.chunks == 1

    assert engine.read_entry(str(vault), PASSWORD, "src/a.txt") == b"alpha\n"
    assert engine.read_entry(str(vault), PASSWORD, "src/zero") == b""

    out = tmp_path / "out" / "renamed.txt"
    result = engine.extract_entry(
        str(vault), PASSWORD, "src/a.txt", str(out), False
    )
    assert result.entries_written == 1
    assert result.bytes_written == 6
    assert out.read_text(encoding="utf-8") == "alpha\n"

    extracted = tmp_path / "everything"
    result = engine.extract_all(str(vault), PASSWORD, str(extracted), False)
    assert result.entries_written == 3
    assert (extracted / "src" / "a.txt").read_text(encoding="utf-8") == "alpha\n"
    assert (extracted / "src" / "sub" / "b.bin").read_bytes() == b"beta\x00\xff"
    assert (extracted / "src" / "empty").is_dir()
    assert (extracted / "src" / "zero").read_bytes() == b""

    report = engine.verify_vault(str(vault), PASSWORD)
    assert report.ok
    assert report.entries_checked == 6
    assert report.chunks_checked == 2
    assert report.bytes_verified == 12


def test_chunking_round_trip(tmp_path: Path):
    vault = make_vault(tmp_path)
    payload = os.urandom(4 * 1024 * 1024 + 123)
    source = tmp_path / "large.bin"
    source.write_bytes(payload)

    engine.add_paths(str(vault), PASSWORD, [str(source)], None, False)
    entry = engine.list_entries(str(vault), PASSWORD)[0]
    assert entry.path == "large.bin"
    assert entry.size == len(payload)
    assert entry.chunks == 2
    assert engine.read_entry(str(vault), PASSWORD, "large.bin") == payload
    assert engine.verify_vault(str(vault), PASSWORD).ok


def test_append_only_and_no_overwrite(tmp_path: Path):
    vault = make_vault(tmp_path)
    source = tmp_path / "one.txt"
    source.write_text("one", encoding="utf-8")
    engine.add_paths(str(vault), PASSWORD, [str(source)], None, False)

    with pytest.raises(engine.VaultError, match="already contains"):
        engine.add_paths(str(vault), PASSWORD, [str(source)], None, False)

    other = tmp_path / "two.txt"
    other.write_text("two", encoding="utf-8")
    with pytest.raises(engine.VaultError, match="already contains"):
        engine.add_paths(
            str(vault), PASSWORD, [str(other)], "one.txt", False
        )

    assert engine.read_entry(str(vault), PASSWORD, "one.txt") == b"one"
    assert len(engine.list_entries(str(vault), PASSWORD)) == 1


def test_destination_collisions_and_traversal_are_rejected(tmp_path: Path):
    vault = make_vault(tmp_path)
    source = tmp_path / "one.txt"
    source.write_text("one", encoding="utf-8")

    with pytest.raises(engine.VaultError, match="unsafe vault path"):
        engine.add_paths(
            str(vault), PASSWORD, [str(source)], "../escape.txt", False
        )
    with pytest.raises(engine.VaultError, match="unsafe vault path"):
        engine.add_paths(
            str(vault), PASSWORD, [str(source)], "/absolute.txt", False
        )

    engine.add_paths(str(vault), PASSWORD, [str(source)], "docs/one.txt", False)
    assert engine.read_entry(str(vault), PASSWORD, "docs/one.txt") == b"one"

    # A later file cannot turn an implicit parent path into a regular file.
    clash = tmp_path / "clash.txt"
    clash.write_text("clash", encoding="utf-8")
    with pytest.raises(engine.VaultError, match="already contains|would be stored"):
        engine.add_paths(str(vault), PASSWORD, [str(clash)], "docs", False)


def test_wrong_password_and_tampered_index(tmp_path: Path):
    vault = make_vault(tmp_path)
    source = tmp_path / "a.txt"
    source.write_text("alpha", encoding="utf-8")
    engine.add_paths(str(vault), PASSWORD, [str(source)], None, False)

    with pytest.raises(engine.VaultError, match="wrong password"):
        engine.list_entries(str(vault), "wrong password")

    data = bytearray(vault.read_bytes())
    # Find the newest header slot, then corrupt a byte in the encrypted index
    # that it points to. The CRC only covers the header, so this exercises the
    # AEAD tag on the index rather than header parsing.
    slots = []
    for slot in (0, 512):
        sequence = int.from_bytes(data[slot + 16 : slot + 24], "little")
        index_offset = int.from_bytes(data[slot + 88 : slot + 96], "little")
        slots.append((sequence, index_offset))
    _, index_offset = max(slots)
    data[index_offset + 5] ^= 0xFF
    vault.write_bytes(data)

    with pytest.raises(engine.VaultError, match="wrong password|corrupt"):
        engine.list_entries(str(vault), PASSWORD)


def test_symlinks_are_skipped(tmp_path: Path):
    if platform.system() == "Windows":
        pytest.skip("symbolic link setup is platform-specific")
    vault = make_vault(tmp_path)
    source = tmp_path / "src"
    source.mkdir()
    (source / "real.txt").write_text("real", encoding="utf-8")
    (source / "link.txt").symlink_to(source / "real.txt")
    (source / "linkdir").symlink_to(source, target_is_directory=True)

    added = engine.add_paths(str(vault), PASSWORD, [str(source)], None, False)
    assert added.files_added == 1
    assert len(added.skipped) == 2
    paths = {entry.path for entry in engine.list_entries(str(vault), PASSWORD)}
    assert paths == {"src", "src/real.txt"}


def test_vault_cannot_be_added_to_itself(tmp_path: Path):
    vault = make_vault(tmp_path)
    with pytest.raises(engine.VaultError, match="cannot be added to itself"):
        engine.add_paths(str(vault), PASSWORD, [str(vault)], None, False)

    source = tmp_path / "src"
    source.mkdir()
    (source / "file.txt").write_text("x", encoding="utf-8")
    with pytest.raises(engine.VaultError, match="vault is inside"):
        engine.add_paths(str(vault), PASSWORD, [str(tmp_path)], None, False)


def test_extract_all_refuses_to_overwrite_the_vault(tmp_path: Path):
    vault = make_vault(tmp_path)
    source = tmp_path / "payload.txt"
    source.write_text("payload", encoding="utf-8")
    engine.add_paths(
        str(vault), PASSWORD, [str(source)], "vault.sbx", False
    )

    with pytest.raises(engine.VaultError, match="overwrite the vault"):
        engine.extract_all(str(vault), PASSWORD, str(tmp_path), False)
    assert vault.exists()


@pytest.mark.skipif(
    platform.system() not in {"Darwin", "Linux"},
    reason="immutable file flags are Unix-specific",
)
def test_immutable_flag_blocks_deletion_and_survives_add(tmp_path: Path):
    vault = make_vault(tmp_path, protect=True)
    status = engine.protection_status(str(vault))
    if not status.protected:
        pytest.skip(f"immutable flags unavailable: {status.detail}")

    with pytest.raises(PermissionError):
        os.remove(vault)
    assert vault.exists()

    rm = subprocess.run(
        ["rm", "-f", str(vault)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert rm.returncode != 0
    assert vault.exists()

    source = tmp_path / "later.txt"
    source.write_text("later", encoding="utf-8")
    added = engine.add_paths(str(vault), PASSWORD, [str(source)], None, True)
    assert added.protection.protected
    assert engine.protection_status(str(vault)).protected
    with pytest.raises(PermissionError):
        os.remove(vault)


def test_short_passphrases_are_rejected(tmp_path: Path):
    vault = tmp_path / "short.sbx"
    with pytest.raises(engine.VaultError, match="at least 8 bytes"):
        engine.create_vault(str(vault), "short", MEMORY_MIB, ITERATIONS, 1, False)
