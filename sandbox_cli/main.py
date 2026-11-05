import click
from rich.console import Console

console = Console()

@click.group()
def cli():
    """Sandbox CLI - A high-performance, undeletable single-file binary vault."""
    pass

@cli.command()
def init():
    """Initialize a new encrypted sandboxed vault."""
    console.print("[bold green]Initializing a secure vault...[/bold green]")

if __name__ == '__main__':
    cli()
