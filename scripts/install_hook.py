"""
Secrets Sentry - Install Pre-commit Hook

Install the secrets detection pre-commit hook locally.
"""

import sys
import subprocess
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich import box

console = Console()


def check_git_repo() -> bool:
    """Check if we're in a git repository."""
    try:
        subprocess.run(
            ['git', 'rev-parse', '--git-dir'],
            capture_output=True,
            check=True
        )
        return True
    except subprocess.CalledProcessError:
        return False


def check_pre_commit_installed() -> bool:
    """Check if pre-commit is installed."""
    try:
        subprocess.run(
            ['pre-commit', '--version'],
            capture_output=True,
            check=True
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def create_pre_commit_config():
    """Create .pre-commit-config.yaml if it doesn't exist."""
    config_file = Path('.pre-commit-config.yaml')

    if config_file.exists():
        console.print("[yellow]ℹ️  .pre-commit-config.yaml already exists[/yellow]")
        console.print("[dim]You may need to manually add the secrets-sentry hook[/dim]")
        return False

    # Create basic config
    config_content = """# Pre-commit hooks configuration
# See https://pre-commit.com for more information

repos:
  - repo: local
    hooks:
      - id: secrets-sentry
        name: Secrets Sentry - Detect hardcoded secrets
        entry: python -m src.hooks.pre_commit
        language: system
        stages: [commit]
        types: [text]
        pass_filenames: false
        always_run: true
"""

    with open(config_file, 'w') as f:
        f.write(config_content)

    console.print(f"[green]✅ Created {config_file}[/green]")
    return True


@click.command()
@click.option(
    '--force',
    is_flag=True,
    help='Force reinstall even if already installed'
)
def install_hook(force):
    """
    Install Secrets Sentry pre-commit hook.

    This will:
    1. Check if pre-commit is installed
    2. Create .pre-commit-config.yaml (if needed)
    3. Run 'pre-commit install' to activate the hook

    Example:
        python -m scripts.install_hook
    """
    try:
        console.print()
        console.print(Panel(
            "[bold]Installing Secrets Sentry Pre-commit Hook[/bold]",
            border_style="cyan",
            box=box.ROUNDED
        ))
        console.print()

        # Check if we're in a git repo
        if not check_git_repo():
            console.print("[red]❌ Not in a git repository![/red]")
            console.print("[dim]Run 'git init' first[/dim]")
            console.print()
            sys.exit(1)

        console.print("[green]✅ Git repository detected[/green]")

        # Check if pre-commit is installed
        if not check_pre_commit_installed():
            console.print("[red]❌ pre-commit not installed[/red]")
            console.print()
            console.print("[bold]Install pre-commit:[/bold]")
            console.print("  pip install pre-commit")
            console.print()
            console.print("[dim]Or see: https://pre-commit.com/#install[/dim]")
            console.print()
            sys.exit(1)

        console.print("[green]✅ pre-commit is installed[/green]")

        # Create .pre-commit-config.yaml
        config_created = create_pre_commit_config()

        # Install the hook
        console.print()
        console.print("[cyan]Installing pre-commit hooks...[/cyan]")

        try:
            result = subprocess.run(
                ['pre-commit', 'install'] + (['--force'] if force else []),
                capture_output=True,
                text=True,
                check=True
            )

            console.print("[green]✅ Pre-commit hooks installed![/green]")

            if result.stdout:
                console.print(f"[dim]{result.stdout.strip()}[/dim]")

        except subprocess.CalledProcessError as e:
            console.print(f"[red]❌ Failed to install hooks:[/red] {e}")
            if e.stderr:
                console.print(f"[dim]{e.stderr}[/dim]")
            sys.exit(1)

        # Success message
        console.print()
        console.print(Panel(
            "[bold green]✅ Installation complete![/bold green]\n\n"
            "The hook will now run automatically before each commit.\n"
            "It will scan staged files and block commits containing secrets.",
            border_style="green",
            box=box.ROUNDED
        ))
        console.print()

        # Usage instructions
        console.print("[bold]Usage:[/bold]")
        console.print("  • Commit normally: [cyan]git commit -m \"message\"[/cyan]")
        console.print("  • Hook will run automatically")
        console.print("  • Bypass if needed: [cyan]git commit --no-verify[/cyan]")
        console.print()
        console.print("[bold]Test the hook:[/bold]")
        console.print("  [cyan]pre-commit run --all-files[/cyan]")
        console.print()

    except KeyboardInterrupt:
        console.print("\n[yellow]Cancelled by user.[/yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"\n[red]Error:[/red] {e}")
        import traceback
        console.print(f"[dim]{traceback.format_exc()}[/dim]")
        sys.exit(1)


if __name__ == "__main__":
    install_hook()
