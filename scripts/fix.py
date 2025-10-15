"""
Secrets Sentry - Interactive Fix Command

Interactively review and fix detected secrets by migrating them to environment variables.
"""

import sys
import os
import re
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.panel import Panel
from rich.table import Table
from rich import box

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.utils.config import load_settings
from src.utils.storage import load_findings, add_migration_entry

console = Console()


def generate_env_var_name(rule: str, file: str, index: int = 0) -> str:
    """
    Generate a sensible environment variable name from rule and context.

    Args:
        rule: The detection rule name
        file: File path for context
        index: Index if multiple secrets of same type

    Returns:
        Suggested environment variable name
    """
    # Clean up rule name
    base_name = rule.upper().replace("-", "_").replace(" ", "_")

    # Common mappings
    name_mappings = {
        "AWS_ACCESS_KEY": "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_KEY": "AWS_SECRET_ACCESS_KEY",
        "OPENAI_API_KEY": "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY": "ANTHROPIC_API_KEY",
        "GITHUB_TOKEN": "GITHUB_TOKEN",
        "SLACK_WEBHOOK": "SLACK_WEBHOOK_URL",
        "DISCORD_WEBHOOK": "DISCORD_WEBHOOK_URL",
        "DATABASE_URL": "DATABASE_URL",
        "POSTGRES_PASSWORD": "POSTGRES_PASSWORD",
        "MYSQL_PASSWORD": "MYSQL_PASSWORD",
        "REDIS_PASSWORD": "REDIS_PASSWORD",
        "JWT_SECRET": "JWT_SECRET_KEY",
        "API_KEY": "API_KEY",
        "API_SECRET": "API_SECRET",
    }

    # Check if we have a direct mapping
    if base_name in name_mappings:
        name = name_mappings[base_name]
    else:
        # Use the base name
        name = base_name

        # Add suffix if needed
        if "KEY" not in name and "TOKEN" not in name and "SECRET" not in name and "PASSWORD" not in name:
            name = f"{name}_KEY"

    # Add index if multiple
    if index > 0:
        name = f"{name}_{index + 1}"

    return name


def generate_instructions(migrations: list[dict]) -> str:
    """
    Generate .env.instructions file content.

    Args:
        migrations: List of migration dictionaries

    Returns:
        Instructions file content
    """
    content = []
    content.append("=" * 70)
    content.append("SECRETS MIGRATION INSTRUCTIONS")
    content.append("=" * 70)
    content.append("")
    content.append("The following secrets were detected and need to be migrated to")
    content.append("environment variables for security.")
    content.append("")
    content.append("NEXT STEPS:")
    content.append("  1. Copy each secret value to your Replit Secrets panel")
    content.append("     (Click the lock icon 🔒 in the left sidebar)")
    content.append("  2. Run: python -m scripts.verify")
    content.append("     (Verify all secrets are set)")
    content.append("  3. Code will be refactored automatically after verification")
    content.append("")
    content.append("=" * 70)
    content.append("SECRETS TO MIGRATE")
    content.append("=" * 70)
    content.append("")

    for i, migration in enumerate(migrations, 1):
        content.append(f"{i}. {migration['env_var_name']}")
        content.append(f"   Location: {migration['file']}:{migration['line']}")
        content.append(f"   Rule: {migration['rule']}")
        content.append(f"   Value: {migration['value_redacted']}")
        content.append(f"   Full Value: {migration.get('value_full', '<masked>')}")
        content.append("")

    content.append("=" * 70)
    content.append("IMPORTANT SECURITY NOTES")
    content.append("=" * 70)
    content.append("")
    content.append("• Store the FULL, unredacted values in Replit Secrets")
    content.append("• Do NOT commit the .env.instructions file to git")
    content.append("• After migration, delete this file: rm .env.instructions")
    content.append("• If secrets were leaked in git history, rotate them immediately")
    content.append("")
    content.append("For help: https://docs.replit.com/hosting/secrets-and-environment-variables")
    content.append("")

    return "\n".join(content)


@click.command()
@click.option(
    '--auto',
    is_flag=True,
    help='Automatically fix all findings without prompting'
)
@click.option(
    '--dry-run',
    is_flag=True,
    help='Preview changes without applying them'
)
@click.option(
    '--input',
    'input_file',
    type=click.Path(exists=True),
    help='Custom findings file (default: data/findings.json)'
)
def fix(auto, dry_run, input_file):
    """
    Interactively review and fix detected secrets.

    This command helps you migrate hardcoded secrets to environment variables.

    Examples:

        # Interactive mode (recommended)
        python -m scripts.fix

        # Auto-fix all findings
        python -m scripts.fix --auto

        # Preview changes without applying
        python -m scripts.fix --dry-run
    """
    try:
        # Load settings
        settings = load_settings()

        # Load findings
        if input_file:
            from src.utils.storage import load_json
            findings = load_json(Path(input_file))
        else:
            findings = load_findings(settings.data_dir)

        if not findings:
            console.print()
            console.print("[yellow]ℹ️  No findings to review.[/yellow]")
            console.print("[dim]Run 'python -m scripts.scan' first to detect secrets.[/dim]")
            console.print()
            sys.exit(0)

        # Filter out filename-only findings (can't be auto-fixed)
        fixable_findings = [f for f in findings if f.get('line', 0) > 0]

        if not fixable_findings:
            console.print()
            console.print("[yellow]ℹ️  No fixable findings (all are filename-based warnings).[/yellow]")
            console.print()
            sys.exit(0)

        # Display header
        console.print()
        console.print(Panel(
            f"[bold]Found {len(fixable_findings)} secret(s) to review[/bold]\n"
            "[dim]Review each finding and decide whether to migrate it to an environment variable.[/dim]",
            title="📝 Secret Remediation",
            border_style="cyan",
            box=box.ROUNDED
        ))
        console.print()

        # Track migrations
        migrations = []
        skipped = []

        # Track env var names to avoid duplicates
        env_var_counts = {}

        # Review each finding
        for i, finding in enumerate(fixable_findings, 1):
            file = finding.get('file', 'unknown')
            line = finding.get('line', 0)
            rule = finding.get('rule', 'unknown')
            snippet = finding.get('snippet', '')
            confidence = finding.get('confidence', 0.0)
            remediation = finding.get('remediation', 'Move to environment variable')

            # Display finding info
            console.print(f"[bold cyan][{i}/{len(fixable_findings)}][/bold cyan] {file}:{line}")
            console.print(f"  [yellow]Rule:[/yellow] {rule}")
            console.print(f"  [yellow]Confidence:[/yellow] {confidence:.2f}")
            console.print(f"  [yellow]Snippet:[/yellow] {snippet}")
            console.print()

            # Generate env var name
            if rule not in env_var_counts:
                env_var_counts[rule] = 0
            else:
                env_var_counts[rule] += 1

            suggested_name = generate_env_var_name(rule, file, env_var_counts[rule])

            console.print(f"  [green]Suggested env var:[/green] [bold]{suggested_name}[/bold]")
            console.print(f"  [green]Remediation:[/green] {remediation}")
            console.print()

            # Prompt for action
            if auto:
                action = 'y'
            elif dry_run:
                action = 'n'
            else:
                action = Prompt.ask(
                    "  Fix this secret?",
                    choices=['y', 'n', 'q', 'a'],
                    default='y',
                    show_choices=True,
                    console=console
                )

            if action == 'q':
                console.print("\n[yellow]Cancelled by user.[/yellow]")
                sys.exit(0)
            elif action == 'a':
                auto = True
                action = 'y'

            if action == 'y':
                # Allow custom env var name
                if not auto and not dry_run:
                    custom_name = Prompt.ask(
                        "  Custom name (press Enter to use suggested)",
                        default=suggested_name,
                        console=console
                    )
                    env_var_name = custom_name or suggested_name
                else:
                    env_var_name = suggested_name

                migrations.append({
                    'file': file,
                    'line': line,
                    'rule': rule,
                    'env_var_name': env_var_name,
                    'value_redacted': snippet,
                    'value_full': '<ask user to provide>',  # Will need manual input
                    'confidence': confidence
                })

                console.print(f"  [green]✅ Marked for fixing[/green]\n")
            else:
                skipped.append(finding)
                console.print(f"  [dim]⏭  Skipped[/dim]\n")

        # Display summary
        console.print()
        console.print("━" * 70)
        console.print()

        if migrations:
            summary_table = Table.grid(padding=(0, 2))
            summary_table.add_column(style="cyan")
            summary_table.add_column(style="bold")

            summary_table.add_row("Secrets to migrate:", f"{len(migrations)}")
            summary_table.add_row("Files to update:", f"{len(set(m['file'] for m in migrations))}")
            summary_table.add_row("Env vars to create:", f"{len(set(m['env_var_name'] for m in migrations))}")
            summary_table.add_row("Skipped:", f"{len(skipped)}")

            console.print(Panel(
                summary_table,
                title="[bold]✨ Fix Summary[/bold]",
                border_style="green",
                box=box.ROUNDED
            ))
            console.print()

            # Generate instructions file
            if not dry_run:
                instructions_file = Path(".env.instructions")
                instructions_content = generate_instructions(migrations)

                with open(instructions_file, 'w') as f:
                    f.write(instructions_content)

                console.print(f"[green]📄 Instructions saved to:[/green] [bold]{instructions_file}[/bold]")
                console.print()

                # Add to migration log
                for migration in migrations:
                    add_migration_entry(
                        file=migration['file'],
                        line=migration['line'],
                        old_value_redacted=migration['value_redacted'],
                        env_var_name=migration['env_var_name'],
                        data_dir=settings.data_dir
                    )

                console.print("[bold]Next steps:[/bold]")
                console.print("  1. Review [cyan].env.instructions[/cyan]")
                console.print("  2. Copy secrets to Replit Secrets panel (lock icon 🔒)")
                console.print("  3. Run: [cyan]python -m scripts.verify[/cyan]")
                console.print("  4. Code will be refactored automatically after verification")
                console.print()
            else:
                console.print("[yellow]🔍 Dry run mode - no changes made[/yellow]")
                console.print()
                console.print("Would create migrations:")
                for m in migrations:
                    console.print(f"  • {m['file']}:{m['line']} → ${m['env_var_name']}")
                console.print()

            sys.exit(0)
        else:
            console.print("[yellow]ℹ️  No secrets were selected for fixing.[/yellow]")
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


if __name__ == "__main__":
    fix()
