"""
Secrets Sentry - Main Scanning Command

Scan your repository for hardcoded secrets and credentials.
"""

import sys
import os
from pathlib import Path

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table
from rich.panel import Panel
from rich import box

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.scanner.scanner import Scanner
from src.scanner.git_scanner import GitScanner
from src.utils.config import load_settings
from src.utils.storage import save_findings

console = Console()


def get_confidence_emoji(confidence: float) -> str:
    """Get emoji for confidence level."""
    if confidence >= 0.9:
        return "[red]🔴[/red]"
    elif confidence >= 0.8:
        return "[orange1]🟠[/orange1]"
    elif confidence >= 0.7:
        return "[yellow]🟡[/yellow]"
    else:
        return "[blue]🔵[/blue]"


def format_confidence_level(confidence: float) -> str:
    """Format confidence level with color."""
    if confidence >= 0.8:
        return f"[red bold]{confidence:.2f}[/red bold]"
    elif confidence >= 0.7:
        return f"[yellow]{confidence:.2f}[/yellow]"
    else:
        return f"[blue]{confidence:.2f}[/blue]"


@click.command()
@click.option(
    '--history',
    is_flag=True,
    help='Scan git commit history instead of working tree'
)
@click.option(
    '--depth',
    default=100,
    type=int,
    help='Number of commits to scan in history (default: 100)',
    show_default=True
)
@click.option(
    '--confidence',
    'confidence_threshold',
    default=0.7,
    type=float,
    help='Minimum confidence threshold for reporting (0.0-1.0)',
    show_default=True
)
@click.option(
    '--exclude',
    'exclude_patterns',
    multiple=True,
    help='Additional patterns to exclude (can be used multiple times)'
)
@click.option(
    '--output',
    'output_file',
    type=click.Path(),
    help='Custom output file path (default: data/findings.json)'
)
@click.option(
    '--no-save',
    is_flag=True,
    help='Do not save results to file'
)
@click.option(
    '--quiet',
    '-q',
    is_flag=True,
    help='Minimal output, only show summary'
)
def scan(history, depth, confidence_threshold, exclude_patterns, output_file, no_save, quiet):
    """
    Scan repository for hardcoded secrets and credentials.

    By default, scans the working tree. Use --history to scan git commit history.

    Examples:

        # Scan working tree
        python -m scripts.scan

        # Scan git history (last 100 commits)
        python -m scripts.scan --history

        # Scan with custom depth and confidence
        python -m scripts.scan --history --depth 500 --confidence 0.8

        # Add custom exclude patterns
        python -m scripts.scan --exclude "tests/**" --exclude "*.test.js"
    """
    try:
        # Load settings
        settings = load_settings()

        # Add custom exclude patterns
        all_exclude_patterns = list(settings.scan.exclude_patterns)
        if exclude_patterns:
            all_exclude_patterns.extend(exclude_patterns)

        findings = []

        if history:
            # Scan git history
            if not quiet:
                console.print()
                console.print("[bold cyan]🔍 Scanning git commit history...[/bold cyan]")
                console.print()

            try:
                git_scanner = GitScanner(
                    repo_path=".",
                    entropy_threshold=settings.scan.entropy_threshold,
                    min_token_length=settings.scan.min_token_length
                )

                if not quiet:
                    with Progress(
                        SpinnerColumn(),
                        TextColumn("[progress.description]{task.description}"),
                        BarColumn(),
                        TaskProgressColumn(),
                        console=console
                    ) as progress:
                        task = progress.add_task(
                            f"Scanning last {depth} commits...",
                            total=depth
                        )

                        # Scan history
                        findings = git_scanner.scan_history(depth=depth)
                        progress.update(task, completed=depth)
                else:
                    findings = git_scanner.scan_history(depth=depth)

            except RuntimeError as e:
                console.print(f"[red]Error:[/red] {e}")
                sys.exit(1)
            except Exception as e:
                console.print(f"[red]Error:[/red] Failed to scan git history: {e}")
                sys.exit(1)
        else:
            # Scan working tree
            if not quiet:
                console.print()
                console.print("[bold cyan]🔍 Scanning repository...[/bold cyan]")
                console.print()

            scanner = Scanner(
                entropy_threshold=settings.scan.entropy_threshold,
                min_token_length=settings.scan.min_token_length,
                exclude_patterns=all_exclude_patterns
            )

            # Get list of files to scan
            files_to_scan = []
            repo_path = Path(".")
            for root, dirs, files in os.walk(repo_path):
                # Filter directories
                dirs[:] = [d for d in dirs if not any(
                    Path(root).joinpath(d).match(pattern)
                    for pattern in all_exclude_patterns
                )]

                for file in files:
                    filepath = os.path.join(root, file)
                    # Check if file matches exclude patterns
                    if not any(Path(filepath).match(pattern) for pattern in all_exclude_patterns):
                        files_to_scan.append(filepath)

            if not quiet:
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    TaskProgressColumn(),
                    console=console
                ) as progress:
                    task = progress.add_task(
                        f"Scanning {len(files_to_scan)} files...",
                        total=len(files_to_scan)
                    )

                    for filepath in files_to_scan:
                        try:
                            file_findings = scanner.scan_file(filepath)
                            findings.extend(file_findings)
                        except Exception:
                            pass  # Skip files that can't be scanned
                        progress.advance(task)
            else:
                findings = scanner.scan_directory(".")

        # Filter by confidence threshold
        filtered_findings = [f for f in findings if f.confidence >= confidence_threshold]

        # Get summary
        if findings:
            summary = Scanner().get_summary(filtered_findings)
        else:
            summary = {
                "total": 0,
                "by_rule": {},
                "by_confidence": {"high": 0, "medium": 0, "low": 0},
                "files_affected": 0,
            }

        # Display results
        if not quiet:
            console.print()

            # Create summary panel
            summary_table = Table.grid(padding=(0, 2))
            summary_table.add_column(style="cyan")
            summary_table.add_column(style="bold")

            summary_table.add_row("Total findings:", f"{summary['total']}")
            summary_table.add_row("High confidence:", f"[red]{summary['by_confidence']['high']}[/red]")
            summary_table.add_row("Medium confidence:", f"[yellow]{summary['by_confidence']['medium']}[/yellow]")
            summary_table.add_row("Low confidence:", f"[blue]{summary['by_confidence']['low']}[/blue]")
            summary_table.add_row("Files affected:", f"{summary['files_affected']}")

            console.print(Panel(
                summary_table,
                title="[bold]📊 Scan Results[/bold]",
                border_style="cyan",
                box=box.ROUNDED
            ))
            console.print()

        # Display findings
        if filtered_findings:
            if not quiet:
                console.print("[bold yellow]⚠️  Findings:[/bold yellow]\n")

                # Group by file
                findings_by_file = {}
                for finding in filtered_findings:
                    if finding.file not in findings_by_file:
                        findings_by_file[finding.file] = []
                    findings_by_file[finding.file].append(finding)

                # Display grouped findings
                for file, file_findings in sorted(findings_by_file.items()):
                    console.print(f"[bold]{file}[/bold]")

                    for finding in sorted(file_findings, key=lambda x: x.line):
                        emoji = get_confidence_emoji(finding.confidence)
                        conf_text = format_confidence_level(finding.confidence)

                        line_info = f"[dim]line {finding.line}[/dim]" if finding.line > 0 else "[dim]filename[/dim]"
                        console.print(
                            f"  {emoji} {line_info}  "
                            f"[cyan]{finding.rule}[/cyan]  "
                            f"{finding.snippet}  "
                            f"({conf_text})"
                        )

                    console.print()

            # Save findings
            if not no_save:
                output_path = output_file or str(settings.findings_file)

                # Convert findings to dict
                findings_data = [f.to_dict() for f in filtered_findings]
                save_findings(findings_data, data_dir=settings.data_dir)

                if not quiet:
                    console.print(f"[green]💾 Results saved to:[/green] {output_path}")
                    console.print()

            # Exit with error code if secrets found
            if summary['by_confidence']['high'] > 0:
                console.print("[red bold]⚠️  High-confidence secrets detected![/red bold]")
                console.print("[dim]Run 'python -m scripts.fix' to start the remediation process.[/dim]")
                console.print()
                sys.exit(1)
            else:
                if not quiet:
                    console.print("[yellow]⚠️  Potential secrets detected.[/yellow]")
                    console.print("[dim]Review findings and run 'python -m scripts.fix' if needed.[/dim]")
                    console.print()
                sys.exit(1)
        else:
            if not quiet:
                console.print("[green bold]✅ No secrets detected![/green bold]")
                console.print("[dim]Your repository looks clean.[/dim]")
                console.print()
            else:
                console.print("No secrets detected.")
            sys.exit(0)

    except KeyboardInterrupt:
        console.print("\n[yellow]Scan cancelled by user.[/yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"\n[red]Error:[/red] {e}")
        if not quiet:
            import traceback
            console.print(f"[dim]{traceback.format_exc()}[/dim]")
        sys.exit(1)


if __name__ == "__main__":
    scan()
