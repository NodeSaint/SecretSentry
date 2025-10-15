"""
Secrets Sentry - Verify Environment Variables

Verify that all required environment variables are set before proceeding with code refactoring.
"""

import sys
import os
from pathlib import Path
from typing import List, Tuple

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Confirm
from rich import box
from rich.syntax import Syntax

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.utils.config import load_settings
from src.utils.storage import load_migration_log
from src.migration.refactor import refactor_multiple_files, RefactorError

console = Console()


def load_env_vars_from_instructions(instructions_file: Path) -> List[str]:
    """
    Parse .env.instructions file to extract environment variable names.

    Args:
        instructions_file: Path to instructions file

    Returns:
        List of environment variable names
    """
    if not instructions_file.exists():
        return []

    env_vars = []
    with open(instructions_file, 'r') as f:
        content = f.read()

    # Parse the file - look for lines like "1. AWS_ACCESS_KEY_ID"
    in_secrets_section = False
    for line in content.split('\n'):
        if 'SECRETS TO MIGRATE' in line:
            in_secrets_section = True
            continue
        if in_secrets_section and line.strip().startswith('='):
            break  # End of secrets section

        if in_secrets_section:
            # Match numbered list items like "1. AWS_ACCESS_KEY_ID"
            line = line.strip()
            if line and line[0].isdigit() and '. ' in line:
                # Extract the env var name (first word after number)
                parts = line.split('. ', 1)
                if len(parts) > 1:
                    env_var = parts[1].split()[0]
                    env_vars.append(env_var)

    return env_vars


def load_migrations_from_instructions(instructions_file: Path) -> List[dict]:
    """
    Parse .env.instructions file to extract full migration data.

    Args:
        instructions_file: Path to instructions file

    Returns:
        List of migration dictionaries
    """
    if not instructions_file.exists():
        return []

    migrations = []
    with open(instructions_file, 'r') as f:
        content = f.read()

    # Parse each migration entry
    current_migration = {}
    in_secrets_section = False

    for line in content.split('\n'):
        if 'SECRETS TO MIGRATE' in line:
            in_secrets_section = True
            continue
        if in_secrets_section and line.strip().startswith('='):
            # End of secrets section
            if current_migration:
                migrations.append(current_migration)
            break

        if in_secrets_section:
            line = line.strip()

            # Start of new migration (numbered item)
            if line and line[0].isdigit() and '. ' in line:
                # Save previous migration
                if current_migration:
                    migrations.append(current_migration)
                    current_migration = {}

                # Extract env var name
                parts = line.split('. ', 1)
                if len(parts) > 1:
                    env_var = parts[1].split()[0]
                    current_migration['env_var_name'] = env_var

            # Parse migration details
            elif line.startswith('Location:'):
                location = line.replace('Location:', '').strip()
                if ':' in location:
                    file_path, line_num = location.rsplit(':', 1)
                    current_migration['file'] = file_path
                    try:
                        current_migration['line'] = int(line_num)
                    except ValueError:
                        current_migration['line'] = 0

            elif line.startswith('Full Value:'):
                full_value = line.replace('Full Value:', '').strip()
                if full_value != '<masked>':
                    current_migration['value_full'] = full_value

    # Don't forget last migration
    if current_migration:
        migrations.append(current_migration)

    return migrations


def check_env_var(var_name: str) -> Tuple[bool, str]:
    """
    Check if an environment variable is set.

    Args:
        var_name: Environment variable name

    Returns:
        Tuple of (is_set, value_preview)
    """
    value = os.environ.get(var_name)
    if value:
        # Show first and last few characters
        if len(value) > 8:
            preview = f"{value[:4]}...{value[-4:]}"
        else:
            preview = "***"
        return True, preview
    return False, ""


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
    '--verbose',
    '-v',
    is_flag=True,
    help='Show values preview for set variables'
)
@click.option(
    '--apply-refactoring',
    is_flag=True,
    help='Automatically apply code refactoring after verification'
)
@click.option(
    '--dry-run',
    is_flag=True,
    help='Show what would be refactored without applying changes'
)
def verify(instructions_file, verbose, apply_refactoring, dry_run):
    """
    Verify that all required environment variables are set.

    Checks environment variables listed in .env.instructions or migration log.

    Examples:

        # Verify all required secrets
        python -m scripts.verify

        # Show value previews
        python -m scripts.verify --verbose

        # Use custom instructions file
        python -m scripts.verify --instructions my-secrets.txt
    """
    try:
        # Load settings
        settings = load_settings()

        # Try to load env vars from instructions file
        instructions_path = Path(instructions_file)
        env_vars_from_instructions = load_env_vars_from_instructions(instructions_path)

        # Also load from migration log
        migration_log = load_migration_log(settings.data_dir)
        env_vars_from_log = []
        if migration_log and 'migrations' in migration_log:
            env_vars_from_log = [
                m['env_var_name']
                for m in migration_log['migrations']
            ]

        # Combine and deduplicate
        all_env_vars = list(set(env_vars_from_instructions + env_vars_from_log))

        if not all_env_vars:
            console.print()
            console.print("[yellow]ℹ️  No environment variables to verify.[/yellow]")
            console.print()
            console.print("[dim]Either:[/dim]")
            console.print("[dim]  1. Run 'python -m scripts.fix' to create migration plan[/dim]")
            console.print("[dim]  2. Create .env.instructions file manually[/dim]")
            console.print()
            sys.exit(0)

        # Display header
        console.print()
        console.print(Panel(
            f"[bold]Checking {len(all_env_vars)} environment variable(s)[/bold]",
            title="🔍 Environment Verification",
            border_style="cyan",
            box=box.ROUNDED
        ))
        console.print()

        # Check each variable
        results = []
        for var_name in sorted(all_env_vars):
            is_set, preview = check_env_var(var_name)
            results.append({
                'name': var_name,
                'is_set': is_set,
                'preview': preview
            })

        # Display results
        table = Table(box=box.ROUNDED, show_header=True, header_style="bold cyan")
        table.add_column("Environment Variable", style="cyan")
        table.add_column("Status", justify="center")
        if verbose:
            table.add_column("Value Preview", style="dim")

        for result in results:
            if result['is_set']:
                status = "[green]✅ Set[/green]"
            else:
                status = "[red]❌ Missing[/red]"

            if verbose:
                table.add_row(result['name'], status, result['preview'])
            else:
                table.add_row(result['name'], status)

        console.print(table)
        console.print()

        # Summary
        total = len(results)
        set_count = sum(1 for r in results if r['is_set'])
        missing_count = total - set_count

        console.print("━" * 70)
        console.print()

        if missing_count == 0:
            # All set!
            console.print(Panel(
                f"[bold green]✅ All {total} environment variable(s) are set![/bold green]\n\n"
                "[dim]You can now proceed with code refactoring.[/dim]",
                border_style="green",
                box=box.ROUNDED
            ))
            console.print()

            # Load migrations to apply refactoring
            migrations = load_migrations_from_instructions(instructions_path)

            # Filter to only migrations with full values
            refactorable_migrations = [
                m for m in migrations
                if 'value_full' in m and m.get('value_full') and m['value_full'] != '<masked>'
            ]

            if refactorable_migrations:
                console.print(f"[cyan]Found {len(refactorable_migrations)} secret(s) that can be refactored automatically.[/cyan]")
                console.print()

                # Determine if we should proceed with refactoring
                proceed_with_refactoring = apply_refactoring

                if not apply_refactoring and not dry_run:
                    # Ask user
                    proceed_with_refactoring = Confirm.ask(
                        "Would you like to refactor your code now to use these environment variables?",
                        default=True,
                        console=console
                    )
                    console.print()

                if proceed_with_refactoring or dry_run:
                    # Apply refactoring
                    console.print("[bold]Refactoring code...[/bold]")
                    console.print()

                    try:
                        # Refactoring will auto-extract secret values from source files using line numbers
                        results = refactor_multiple_files(
                            migrations=refactorable_migrations,
                            dry_run=dry_run,
                            create_backups=True
                        )

                        # Display results
                        success_count = sum(1 for r in results if r['success'])
                        failed_count = len(results) - success_count

                        for i, result in enumerate(results, 1):
                            file_path = result['file']
                            env_var_name = result['env_var_name']

                            if result['success']:
                                console.print(f"[green]✅ [{i}/{len(results)}] {file_path}[/green]")
                                console.print(f"   Replaced secret with: [cyan]os.getenv('{env_var_name}')[/cyan]")

                                if result.get('backup_path'):
                                    console.print(f"   Backup: [dim]{result['backup_path']}[/dim]")

                                # Show diff if requested
                                if verbose and result.get('diff'):
                                    console.print()
                                    console.print("[bold]Diff:[/bold]")
                                    syntax = Syntax(result['diff'], "diff", theme="monokai", line_numbers=False)
                                    console.print(syntax)
                                console.print()
                            else:
                                console.print(f"[red]❌ [{i}/{len(results)}] {file_path}[/red]")
                                console.print(f"   Error: {result.get('error', 'Unknown error')}")
                                console.print()

                        # Summary
                        console.print("━" * 70)
                        console.print()

                        if dry_run:
                            console.print(Panel(
                                f"[bold cyan]🔍 Dry run complete[/bold cyan]\n\n"
                                f"Would refactor {success_count} file(s)\n"
                                f"{failed_count} file(s) would fail",
                                border_style="cyan",
                                box=box.ROUNDED
                            ))
                        elif failed_count == 0:
                            console.print(Panel(
                                f"[bold green]✅ Successfully refactored {success_count} file(s)![/bold green]\n\n"
                                "[dim]Your code now uses environment variables for secrets.[/dim]",
                                border_style="green",
                                box=box.ROUNDED
                            ))
                        else:
                            console.print(Panel(
                                f"[bold yellow]⚠️  Partially successful[/bold yellow]\n\n"
                                f"Refactored: {success_count} file(s)\n"
                                f"Failed: {failed_count} file(s)",
                                border_style="yellow",
                                box=box.ROUNDED
                            ))

                        console.print()

                        if not dry_run:
                            console.print("[bold]Next steps:[/bold]")
                            console.print("  1. Test your application to verify everything works")
                            console.print("  2. Review the changes with: [cyan]git diff[/cyan]")
                            console.print("  3. If something broke, backups are in [cyan].backup/[/cyan]")
                            console.print("  4. Delete sensitive files: [cyan]rm .env.instructions[/cyan]")
                            console.print()

                    except Exception as e:
                        console.print(f"[red]Error during refactoring:[/red] {e}")
                        import traceback
                        console.print(f"[dim]{traceback.format_exc()}[/dim]")
                        sys.exit(1)
                else:
                    # User declined refactoring
                    console.print("[bold]Next steps:[/bold]")
                    console.print("  1. Run: [cyan]python -m scripts.verify --apply-refactoring[/cyan]")
                    console.print("     (When ready to refactor your code)")
                    console.print("  2. Or run: [cyan]python -m scripts.verify --dry-run[/cyan]")
                    console.print("     (To preview changes first)")
                    console.print()
            else:
                # No refactorable migrations (values not in instructions file)
                console.print("[yellow]ℹ️  Automatic refactoring not available.[/yellow]")
                console.print("[dim]The .env.instructions file doesn't contain secret values.[/dim]")
                console.print()
                console.print("[bold]Next steps:[/bold]")
                console.print("  1. Test your application with the environment variables")
                console.print("  2. Manually refactor code to use [cyan]os.getenv()[/cyan]")
                console.print("  3. Delete sensitive files: [cyan]rm .env.instructions[/cyan]")
                console.print()

            sys.exit(0)
        else:
            # Some missing
            console.print(Panel(
                f"[bold yellow]⚠️  Status: {set_count}/{total} variable(s) set[/bold yellow]\n\n"
                f"[red]{missing_count} variable(s) missing[/red]",
                border_style="yellow",
                box=box.ROUNDED
            ))
            console.print()

            # List missing variables
            missing_vars = [r['name'] for r in results if not r['is_set']]
            console.print("[bold red]Missing variables:[/bold red]")
            for var in missing_vars:
                console.print(f"  • [red]{var}[/red]")
            console.print()

            # Instructions
            console.print("[bold]How to add secrets in Replit:[/bold]")
            console.print("  1. Click the lock icon (🔒) in the left sidebar")
            console.print("  2. Click '+ New Secret'")
            console.print("  3. Enter the variable name and value")
            console.print("  4. Click 'Add'")
            console.print("  5. Restart your Repl to load the new secrets")
            console.print()

            console.print("[dim]After adding all secrets, run this command again to verify.[/dim]")
            console.print()

            sys.exit(1)

    except KeyboardInterrupt:
        console.print("\n[yellow]Cancelled by user.[/yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"\n[red]Error:[/red] {e}")
        import traceback
        console.print(f"[dim]{traceback.format_exc()}[/dim]")
        sys.exit(1)


if __name__ == "__main__":
    verify()
