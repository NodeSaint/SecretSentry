"""
Secrets Sentry - Secret Copy Utility

Interactive clipboard utility to help copy secrets to Replit Secrets panel.
"""

import sys
import os
import time
from pathlib import Path
from typing import List, Dict

import click
from rich.console import Console
from rich.prompt import Prompt
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.utils.config import load_settings
from src.utils.storage import load_migration_log

console = Console()


def check_pyperclip() -> bool:
    """Check if pyperclip is available."""
    try:
        import pyperclip
        return True
    except ImportError:
        return False


def copy_to_clipboard(text: str) -> bool:
    """
    Copy text to clipboard.

    Args:
        text: Text to copy

    Returns:
        True if successful, False otherwise
    """
    try:
        import pyperclip
        pyperclip.copy(text)
        return True
    except Exception as e:
        console.print(f"[red]Failed to copy:[/red] {e}")
        return False


def load_secrets_from_instructions(instructions_file: Path) -> List[Dict[str, str]]:
    """
    Parse .env.instructions file to extract secrets.

    Args:
        instructions_file: Path to instructions file

    Returns:
        List of secret dictionaries with 'name', 'value', 'location', 'rule'
    """
    if not instructions_file.exists():
        return []

    secrets = []
    with open(instructions_file, 'r') as f:
        content = f.read()

    # Parse the file
    in_secrets_section = False
    current_secret = None

    for line in content.split('\n'):
        if 'SECRETS TO MIGRATE' in line:
            in_secrets_section = True
            continue
        if in_secrets_section and line.strip().startswith('='):
            if current_secret:
                secrets.append(current_secret)
            break  # End of secrets section

        if in_secrets_section:
            line = line.strip()

            # Start of new secret (numbered list)
            if line and line[0].isdigit() and '. ' in line:
                if current_secret:
                    secrets.append(current_secret)

                parts = line.split('. ', 1)
                if len(parts) > 1:
                    env_var = parts[1].split()[0]
                    current_secret = {
                        'name': env_var,
                        'value': None,
                        'location': None,
                        'rule': None
                    }

            # Parse details
            elif current_secret and line:
                if line.startswith('Location:'):
                    current_secret['location'] = line.replace('Location:', '').strip()
                elif line.startswith('Rule:'):
                    current_secret['rule'] = line.replace('Rule:', '').strip()
                elif line.startswith('Full Value:'):
                    value = line.replace('Full Value:', '').strip()
                    # Don't use placeholder values
                    if value not in ['<masked>', '<ask user to provide>', '']:
                        current_secret['value'] = value

    if current_secret:
        secrets.append(current_secret)

    return secrets


@click.command()
@click.option(
    '--instructions',
    'instructions_file',
    type=click.Path(),
    default='.env.instructions',
    help='Path to instructions file (default: .env.instructions)',
    show_default=True
)
@click.option(
    '--auto-advance',
    is_flag=True,
    help='Automatically advance after copying (3 second delay)'
)
def secrets_copy(instructions_file, auto_advance):
    """
    Interactive utility to copy secrets to Replit Secrets panel.

    Helps you copy each secret to clipboard one by one, pausing for you to
    paste it into the Replit Secrets panel.

    Examples:

        # Interactive mode
        python -m scripts.secrets_copy

        # Auto-advance mode
        python -m scripts.secrets_copy --auto-advance
    """
    try:
        # Check pyperclip
        if not check_pyperclip():
            console.print()
            console.print("[red]Error:[/red] pyperclip is not installed")
            console.print("[dim]Install with: pip install pyperclip[/dim]")
            console.print()
            sys.exit(1)

        # Load settings
        settings = load_settings()

        # Load secrets from instructions file
        instructions_path = Path(instructions_file)
        secrets = load_secrets_from_instructions(instructions_path)

        # Also check migration log for additional context
        migration_log = load_migration_log(settings.data_dir)
        if migration_log and 'migrations' in migration_log:
            # Enhance secrets with migration log data if available
            for secret in secrets:
                matching = [
                    m for m in migration_log['migrations']
                    if m['env_var_name'] == secret['name']
                ]
                if matching:
                    migration = matching[0]
                    if not secret['location']:
                        secret['location'] = f"{migration['file']}:{migration['line']}"
                    if not secret['rule']:
                        secret['rule'] = migration.get('rule', 'Unknown')

        if not secrets:
            console.print()
            console.print("[yellow]ℹ️  No secrets found to copy.[/yellow]")
            console.print()
            console.print("[dim]Make sure you have:[/dim]")
            console.print(f"[dim]  1. Run 'python -m scripts.fix' to create migration plan[/dim]")
            console.print(f"[dim]  2. Check that {instructions_file} exists[/dim]")
            console.print()
            sys.exit(0)

        # Display header
        console.print()
        console.print(Panel(
            f"[bold]This utility will help you copy {len(secrets)} secret(s) to Replit[/bold]\n\n"
            "[dim]For each secret, we'll:[/dim]\n"
            "[dim]  1. Copy the key name to clipboard[/dim]\n"
            "[dim]  2. Wait for you to paste it in Replit[/dim]\n"
            "[dim]  3. Then copy the value to clipboard[/dim]\n"
            "[dim]  4. Wait for you to paste and save[/dim]",
            title="📋 Secret Copy Utility",
            border_style="cyan",
            box=box.ROUNDED
        ))
        console.print()

        console.print("[bold]How to add secrets in Replit:[/bold]")
        console.print("  1. Click the lock icon (🔒) in the left sidebar")
        console.print("  2. Click '+ New Secret'")
        console.print("  3. Paste the key name when prompted")
        console.print("  4. Paste the value when prompted")
        console.print("  5. Click 'Add'")
        console.print()

        # Ask to proceed
        if not Confirm.ask("Ready to start?", default=True, console=console):
            console.print("[yellow]Cancelled.[/yellow]")
            sys.exit(0)

        console.print()

        # Track progress
        copied_secrets = []
        skipped_secrets = []

        # Process each secret
        for i, secret in enumerate(secrets, 1):
            console.print("━" * 70)
            console.print()
            console.print(f"[bold cyan][{i}/{len(secrets)}][/bold cyan] [bold]{secret['name']}[/bold]")

            if secret['location']:
                console.print(f"  [dim]Location: {secret['location']}[/dim]")
            if secret['rule']:
                console.print(f"  [dim]Rule: {secret['rule']}[/dim]")
            console.print()

            # Check if already set
            if os.environ.get(secret['name']):
                console.print(f"  [yellow]⚠️  Already set in environment[/yellow]")
                console.print(f"  [dim]Current value: {os.environ.get(secret['name'])[:4]}...{os.environ.get(secret['name'])[-4:]}[/dim]")
                console.print()

                if not Confirm.ask("  Override?", default=False, console=console):
                    console.print(f"  [dim]⏭  Skipped[/dim]")
                    skipped_secrets.append(secret['name'])
                    console.print()
                    continue

            # Step 1: Copy key name
            console.print(f"  [cyan]Step 1:[/cyan] Copying key name to clipboard...")
            if copy_to_clipboard(secret['name']):
                console.print(f"  [green]✅ Copied:[/green] [bold]{secret['name']}[/bold]")
                console.print()
                console.print("  [dim]Now in Replit:[/dim]")
                console.print("    [dim]1. Click '+ New Secret'[/dim]")
                console.print("    [dim]2. Paste the key name (Cmd+V / Ctrl+V)[/dim]")
                console.print()

                if auto_advance:
                    with Progress(
                        SpinnerColumn(),
                        TextColumn("[progress.description]{task.description}"),
                        console=console
                    ) as progress:
                        task = progress.add_task("Waiting 3 seconds...", total=100)
                        for _ in range(30):
                            time.sleep(0.1)
                            progress.update(task, advance=3.33)
                else:
                    Prompt.ask("  Press Enter when ready for value", default="", console=console)

                console.print()

                # Step 2: Handle value
                if secret['value'] and secret['value'] not in ['<masked>', '<ask user to provide>']:
                    # We have the value
                    console.print(f"  [cyan]Step 2:[/cyan] Copying value to clipboard...")
                    if copy_to_clipboard(secret['value']):
                        # Show preview
                        if len(secret['value']) > 8:
                            preview = f"{secret['value'][:4]}...{secret['value'][-4:]}"
                        else:
                            preview = "***"

                        console.print(f"  [green]✅ Copied value:[/green] {preview}")
                        console.print()
                        console.print("  [dim]Now in Replit:[/dim]")
                        console.print("    [dim]1. Paste the value (Cmd+V / Ctrl+V)[/dim]")
                        console.print("    [dim]2. Click 'Add'[/dim]")
                        console.print()

                        copied_secrets.append(secret['name'])
                    else:
                        console.print(f"  [red]❌ Failed to copy value[/red]")
                        skipped_secrets.append(secret['name'])
                else:
                    # Need manual input
                    console.print(f"  [yellow]⚠️  Value not available in instructions file[/yellow]")
                    console.print(f"  [dim]You'll need to manually enter the value in Replit[/dim]")
                    console.print()

                    if Confirm.ask("  Mark as completed?", default=True, console=console):
                        copied_secrets.append(secret['name'])
                    else:
                        skipped_secrets.append(secret['name'])

                if not auto_advance:
                    Prompt.ask("  Press Enter to continue", default="", console=console)
                else:
                    time.sleep(1)

            else:
                console.print(f"  [red]❌ Failed to copy[/red]")
                skipped_secrets.append(secret['name'])

            console.print()

        # Summary
        console.print("━" * 70)
        console.print()

        summary_table = Table.grid(padding=(0, 2))
        summary_table.add_column(style="cyan")
        summary_table.add_column(style="bold")

        summary_table.add_row("Total secrets:", f"{len(secrets)}")
        summary_table.add_row("Copied:", f"[green]{len(copied_secrets)}[/green]")
        summary_table.add_row("Skipped:", f"[yellow]{len(skipped_secrets)}[/yellow]")

        console.print(Panel(
            summary_table,
            title="[bold]✨ Summary[/bold]",
            border_style="green",
            box=box.ROUNDED
        ))
        console.print()

        if copied_secrets:
            console.print("[bold]Next steps:[/bold]")
            console.print("  1. Verify secrets are set: [cyan]python -m scripts.verify[/cyan]")
            console.print("  2. Restart your Repl to load the new secrets")
            console.print("  3. Test your application")
            console.print()

        if skipped_secrets:
            console.print("[yellow]Skipped secrets:[/yellow]")
            for name in skipped_secrets:
                console.print(f"  • {name}")
            console.print()

        sys.exit(0)

    except KeyboardInterrupt:
        console.print("\n[yellow]Cancelled by user.[/yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"\n[red]Error:[/red] {e}")
        import traceback
        console.print(f"[dim]{traceback.format_exc()}[/dim]")
        sys.exit(1)


# Import Confirm from rich.prompt
from rich.prompt import Confirm


if __name__ == "__main__":
    secrets_copy()
