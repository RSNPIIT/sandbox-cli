# SPDX-License-Identifier: GPL-3.0-or-later

"""Command-line interface for Sandbox CLI."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click
from rich.markup import escape

from . import __version__
from . import ui

try:
    from . import sandbox_engine as engine
    _ENGINE_IMPORT_ERROR = None
except ImportError as exc:  # pragma: no cover - exercised only on broken installs
    engine = None
    _ENGINE_IMPORT_ERROR = exc


def _get_engine():
    if engine is None:
        raise click.ClickException(
            "the Rust extension module is not built. Run `maturin develop --release` "
            f"inside the project's virtual environment. ({_ENGINE_IMPORT_ERROR})"
        )
    return engine


def _call(function, *args, **kwargs):
    engine_module = _get_engine()
    try:
        return function(*args, **kwargs)
    except engine_module.VaultError as exc:
        raise click.ClickException(str(exc)) from exc


def _require_vault(path: Path, must_exist: bool = True) -> None:
    if must_exist and not path.exists():
        raise click.ClickException(f"vault does not exist: {path}")
    if not must_exist and path.exists():
        raise click.ClickException(f"vault already exists: {path}")
    if path.exists() and path.is_dir():
        raise click.ClickException(f"vault path is a directory, not a file: {path}")


def _password_from_context(ctx, confirm: bool = False) -> str:
    return ui.read_password(
        password_stdin=bool(ctx.obj and ctx.obj.get("password_stdin")),
        confirm=confirm,
    )


@click.group(
    context_settings={"help_option_names": ["-h", "--help"], "max_content_width": 100},
    epilog=(
        "Examples:\n"
        "  sandbox-cli init private.sbx\n"
        "  sandbox-cli add private.sbx ~/Documents/notes\n"
        "  sandbox-cli list private.sbx\n"
        "  sandbox-cli extract private.sbx notes/todo.txt -o ./todo.txt\n"
        "  sandbox-cli extract-all private.sbx ./restored\n"
        "  sandbox-cli verify private.sbx"
    ),
)
@click.version_option(__version__, prog_name="sandbox-cli")
@click.option(
    "--password-stdin",
    is_flag=True,
    help="Read the passphrase from stdin. Intended for scripts and tests.",
)
@click.pass_context
def cli(ctx, password_stdin: bool):
    """An encrypted, append-only, deletion-resistant single-file vault.

    The vault is one encrypted file, not a mounted directory. Files can be
    added and extracted with the passphrase, but this tool provides no delete
    or overwrite operation. The file is marked immutable while it is idle so
    that ordinary users and GUI file managers cannot remove it.
    """
    ctx.ensure_object(dict)
    ctx.obj["password_stdin"] = password_stdin


@cli.command()
@click.argument("vault", type=click.Path(path_type=Path, dir_okay=False))
@click.option("--memory-mib", type=click.IntRange(8, 1024), default=64, show_default=True)
@click.option("--iterations", type=click.IntRange(1, 64), default=3, show_default=True)
@click.option("--parallelism", type=click.IntRange(1, 8), default=1, show_default=True)
@click.option(
    "--no-protect",
    is_flag=True,
    help="Do not mark the vault immutable. The vault remains encrypted but can be deleted.",
)
@click.pass_context
def init(ctx, vault: Path, memory_mib: int, iterations: int, parallelism: int, no_protect: bool):
    """Create a new encrypted vault at VAULT."""
    _get_engine()
    _require_vault(vault, must_exist=False)
    password = _password_from_context(ctx, confirm=True)
    with ui.console.status("[cyan]Deriving key and creating vault...[/cyan]"):
        result = _call(
            engine.create_vault,
            str(vault),
            password,
            memory_mib,
            iterations,
            parallelism,
            not no_protect,
        )
    ui.console.print(f"[bold green]Created vault[/bold green] {escape(str(vault))}")
    ui.console.print(f"Vault ID: [dim]{result.vault_id}[/dim]")
    ui.print_protection(result.protection)
    ui.print_warning(result.warning)
    ui.console.print(
        f"\nNext: [bold]sandbox-cli add {escape(str(vault))} PATH[/bold] "
        "(you will be asked for the passphrase again)."
    )


@cli.command()
@click.argument("vault", type=click.Path(path_type=Path, dir_okay=False))
@click.argument(
    "sources",
    nargs=-1,
    required=True,
    type=click.Path(exists=True, path_type=Path, allow_dash=False),
)
@click.option(
    "--as",
    "destination",
    default=None,
    metavar="VAULT_PATH",
    help="Store the single source under this path inside the vault.",
)
@click.pass_context
def add(ctx, vault: Path, sources: tuple[Path, ...], destination: str | None):
    """Encrypt SOURCES and append them to VAULT.

    Adding is append-only. Existing entries are never overwritten or removed.
    Directory sources are walked recursively; symbolic links are skipped.
    """
    _get_engine()
    _require_vault(vault)
    if destination is not None and len(sources) != 1:
        raise click.UsageError("--as can only be used with exactly one source")
    password = _password_from_context(ctx)
    with ui.console.status("[cyan]Encrypting and appending files...[/cyan]"):
        result = _call(
            engine.add_paths,
            str(vault),
            password,
            [str(source) for source in sources],
            destination,
            True,
        )
    ui.print_add_summary(result)


@cli.command("list")
@click.argument("vault", type=click.Path(path_type=Path, dir_okay=False))
@click.option("--json", "as_json", is_flag=True, help="Print machine-readable JSON.")
@click.pass_context
def list_command(ctx, vault: Path, as_json: bool):
    """List the decrypted filenames and metadata inside VAULT."""
    _get_engine()
    _require_vault(vault)
    password = _password_from_context(ctx)
    with ui.console.status("[cyan]Unlocking index...[/cyan]"):
        entries = _call(engine.list_entries, str(vault), password)
    if as_json:
        payload = [
            {
                "path": entry.path,
                "kind": entry.kind,
                "size": entry.size,
                "stored_size": entry.stored_size,
                "mode": entry.mode,
                "modified_unix": entry.mtime_secs,
                "chunks": entry.chunks,
            }
            for entry in entries
        ]
        click.echo(json.dumps(payload, indent=2))
        return
    ui.print_entries(entries)


@cli.command()
@click.argument("vault", type=click.Path(path_type=Path, dir_okay=False))
def info(vault: Path):
    """Show vault format, KDF settings, size, and protection state.

    This command does not require the passphrase and cannot see filenames.
    """
    _get_engine()
    _require_vault(vault)
    vault_info = _call(engine.vault_info, str(vault))
    ui.print_info(vault, vault_info)


@cli.command()
@click.argument("vault", type=click.Path(path_type=Path, dir_okay=False))
@click.argument("entry")
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    default=None,
    help="Destination file, or an existing directory in which to place it.",
)
@click.option("--force", is_flag=True, help="Replace an existing output file.")
@click.pass_context
def extract(ctx, vault: Path, entry: str, output: Path | None, force: bool):
    """Extract one file from VAULT to disk."""
    _get_engine()
    _require_vault(vault)
    if not entry:
        raise click.BadParameter("entry name cannot be empty", param_hint="ENTRY")

    destination = output
    if destination is None:
        destination = Path(Path(entry).name)
    elif destination.is_dir():
        destination = destination / Path(entry).name
    if destination.exists() and destination.is_dir():
        raise click.ClickException(f"output path is a directory: {destination}")

    password = _password_from_context(ctx)
    with ui.console.status("[cyan]Authenticating and extracting...[/cyan]"):
        result = _call(
            engine.extract_entry,
            str(vault),
            password,
            entry,
            str(destination),
            force,
        )
    ui.console.print(
        f"[bold green]Extracted[/bold green] {escape(entry)} -> "
        f"{escape(str(destination))} "
        f"([cyan]{ui.human_size(result.bytes_written)}[/cyan])"
    )


@cli.command("extract-all")
@click.argument("vault", type=click.Path(path_type=Path, dir_okay=False))
@click.argument("destination", type=click.Path(path_type=Path))
@click.option("--force", is_flag=True, help="Replace files that already exist.")
@click.pass_context
def extract_all(ctx, vault: Path, destination: Path, force: bool):
    """Extract every file from VAULT into DESTINATION directory."""
    _get_engine()
    _require_vault(vault)
    if destination.exists() and not destination.is_dir():
        raise click.ClickException(f"destination is not a directory: {destination}")
    password = _password_from_context(ctx)
    with ui.console.status("[cyan]Authenticating and extracting...[/cyan]"):
        result = _call(
            engine.extract_all,
            str(vault),
            password,
            str(destination),
            force,
        )
    ui.console.print(
        f"[bold green]Extracted[/bold green] {result.entries_written} file(s) "
        f"({ui.human_size(result.bytes_written)}) into {escape(str(destination))}"
    )


@cli.command()
@click.argument("vault", type=click.Path(path_type=Path, dir_okay=False))
@click.argument("entry")
@click.pass_context
def cat(ctx, vault: Path, entry: str):
    """Write one decrypted file to stdout (useful in pipelines)."""
    _get_engine()
    _require_vault(vault)
    password = _password_from_context(ctx)
    data = _call(engine.read_entry, str(vault), password, entry)
    if hasattr(sys.stdout, "buffer"):
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
    else:  # pragma: no cover - unusual embedded Python environments
        click.echo(data)


@cli.command()
@click.argument("vault", type=click.Path(path_type=Path, dir_okay=False))
@click.pass_context
def verify(ctx, vault: Path):
    """Authenticate and decompress every block in VAULT."""
    _get_engine()
    _require_vault(vault)
    password = _password_from_context(ctx)
    with ui.console.status("[cyan]Verifying every encrypted block...[/cyan]"):
        report = _call(engine.verify_vault, str(vault), password)
    ui.print_verify_report(report)
    if not report.ok:
        raise click.exceptions.Exit(1)


@cli.command()
@click.argument("vault", type=click.Path(path_type=Path, dir_okay=False))
def protect(vault: Path):
    """Re-apply the operating-system immutable flag to VAULT.

    The passphrase is not needed because this only locks the file; it does not
    unlock or reveal vault contents.
    """
    _get_engine()
    _require_vault(vault)
    status = _call(engine.protect_vault, str(vault))
    ui.print_protection(status)


if __name__ == "__main__":  # pragma: no cover
    cli()
