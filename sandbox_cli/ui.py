# SPDX-License-Identifier: GPL-3.0-or-later

"""Presentation helpers for Sandbox CLI."""

from __future__ import annotations

import sys
from datetime import datetime
from typing import Iterable, Optional

import click
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

console = Console(highlight=False)
error_console = Console(stderr=True, highlight=False)


def read_password(password_stdin: bool, confirm: bool = False) -> str:
    """Read a passphrase without ever putting it in argv or an environment variable."""
    if password_stdin:
        password = sys.stdin.readline()
        if password == "":
            raise click.ClickException("expected a passphrase on stdin")
        password = password.rstrip("\r\n")
    else:
        password = click.prompt(
            "Passphrase",
            hide_input=True,
            confirmation_prompt=confirm,
            type=str,
            err=True,
        )
    if not password:
        raise click.ClickException("passphrase cannot be empty")
    return password


def human_size(size: int) -> str:
    value = float(size)
    units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"]
    for unit in units:
        if value < 1024 or unit == units[-1]:
            if unit == "B":
                return f"{int(value)} B"
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{size} B"


def format_timestamp(timestamp: int) -> str:
    try:
        return datetime.fromtimestamp(timestamp).astimezone().strftime(
            "%Y-%m-%d %H:%M:%S %Z"
        )
    except (OverflowError, OSError, ValueError):
        return "unknown"


def mode_string(mode: int, is_dir: bool = False) -> str:
    bits = []
    for shift in (6, 3, 0):
        bits.append("r" if mode & (4 << shift) else "-")
        bits.append("w" if mode & (2 << shift) else "-")
        bits.append("x" if mode & (1 << shift) else "-")
    return ("d" if is_dir else "-") + "".join(bits)


def protection_text(protection) -> Text:
    if protection.protected:
        return Text(f"immutable ({protection.method})", style="bold green")
    if protection.supported:
        return Text("NOT protected", style="bold red")
    return Text(f"unavailable on this platform ({protection.method})", style="bold yellow")


def print_protection(protection) -> None:
    text = Text("Deletion protection: ")
    text.append_text(protection_text(protection))
    console.print(text)
    if protection.detail:
        console.print(f"  [yellow]{escape(protection.detail)}[/yellow]")
    if not protection.protected:
        if protection.supported:
            console.print(
                "  [yellow]The vault is still encrypted, but it can be deleted by its "
                "owner. Run `sandbox-cli protect VAULT` to try again.[/yellow]"
            )
        else:
            console.print(
                "  [yellow]The vault is encrypted, but this platform cannot make it "
                "immutable. Back it up and restrict directory permissions.[/yellow]"
            )


def print_warning(message: Optional[str]) -> None:
    if message:
        console.print(f"[bold yellow]Warning:[/bold yellow] {escape(message)}")


def print_add_summary(result) -> None:
    pieces = []
    if result.files_added:
        pieces.append(f"{result.files_added} file(s)")
    if result.dirs_added:
        pieces.append(f"{result.dirs_added} director{'y' if result.dirs_added == 1 else 'ies'}")
    added = ", ".join(pieces) if pieces else "nothing"
    console.print(
        f"[bold green]Added[/bold green] {added} "
        f"([cyan]{human_size(result.bytes_added)}[/cyan] plaintext, "
        f"[cyan]{human_size(result.stored_bytes_added)}[/cyan] encrypted blocks)."
    )
    console.print(f"Vault now contains [bold]{result.total_entries}[/bold] entries.")
    for skipped in result.skipped[:20]:
        console.print(f"  [yellow]skipped:[/yellow] {escape(skipped)}")
    if len(result.skipped) > 20:
        console.print(f"  [yellow]... and {len(result.skipped) - 20} more skipped[/yellow]")
    print_protection(result.protection)
    print_warning(result.warning)


def print_entries(entries: Iterable) -> None:
    entries = list(entries)
    if not entries:
        console.print("[dim]The vault is empty.[/dim]")
        return

    table = Table(show_header=True, header_style="bold", box=None, pad_edge=False)
    table.add_column("Mode", style="dim", no_wrap=True)
    table.add_column("Type", no_wrap=True)
    table.add_column("Path", overflow="fold")
    table.add_column("Size", justify="right", no_wrap=True)
    table.add_column("Stored", justify="right", no_wrap=True)
    table.add_column("Modified", no_wrap=True)

    files = 0
    dirs = 0
    total_size = 0
    total_stored = 0
    for entry in entries:
        is_dir = entry.kind == "dir"
        files += 0 if is_dir else 1
        dirs += 1 if is_dir else 0
        total_size += entry.size
        total_stored += entry.stored_size
        table.add_row(
            mode_string(entry.mode, is_dir),
            "dir" if is_dir else "file",
            escape(entry.path),
            "-" if is_dir else human_size(entry.size),
            "-" if is_dir else human_size(entry.stored_size),
            format_timestamp(entry.mtime_secs),
        )
    console.print(table)
    console.print(
        f"[dim]{files} file(s), {dirs} director{'y' if dirs == 1 else 'ies'}, "
        f"{human_size(total_size)} plaintext, {human_size(total_stored)} stored[/dim]"
    )


def print_info(vault_path, info) -> None:
    table = Table(show_header=False, box=None, pad_edge=False)
    table.add_column("Field", style="bold cyan", no_wrap=True)
    table.add_column("Value", overflow="fold")
    table.add_row("Vault", escape(str(vault_path.resolve())))
    table.add_row("Encrypted size", human_size(info.file_size))
    table.add_row("Format", f"v{info.format_version}")
    table.add_row("Vault ID", info.vault_id)
    table.add_row(
        "KDF",
        f"Argon2id, {info.kdf_memory_kib / 1024:.0f} MiB, "
        f"{info.kdf_iterations} iteration(s), {info.kdf_parallelism} lane(s)",
    )
    table.add_row("Header generation", str(info.sequence))
    table.add_row("Created", format_timestamp(info.created_at))
    table.add_row("Last update", format_timestamp(info.updated_at))
    protection = Text()
    protection.append_text(protection_text(info.protection))
    table.add_row("Deletion protection", protection)
    console.print(Panel(table, title="[bold]Sandbox vault[/bold]", border_style="cyan"))
    if info.protection.detail:
        console.print(f"[yellow]{escape(info.protection.detail)}[/yellow]")
    console.print(
        "[dim]Entry names and metadata are encrypted. Run `sandbox-cli list VAULT` "
        "with the passphrase to see them.[/dim]"
    )


def print_verify_report(report) -> None:
    if report.ok:
        console.print(
            f"[bold green]Vault is intact.[/bold green] Checked "
            f"{report.entries_checked} entries, {report.chunks_checked} blocks, "
            f"{human_size(report.bytes_verified)} of plaintext."
        )
        return
    console.print(
        f"[bold red]Verification failed.[/bold red] Checked "
        f"{report.entries_checked} entries and {report.chunks_checked} blocks."
    )
    for problem in report.problems:
        console.print(f"  [red]- {escape(problem)}[/red]")
    if report.problems_truncated:
        console.print("  [red]... additional problems were omitted.[/red]")
