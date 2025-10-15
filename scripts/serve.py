"""
Secrets Sentry - Dashboard Server

Start the web dashboard to view and manage secret findings.
"""

import sys
import socket
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich import box

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

console = Console()


def get_local_ip() -> str:
    """Get the local network IP address."""
    try:
        # Create a socket to determine local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Connect to a public DNS server (doesn't actually send data)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return "127.0.0.1"


def check_uvicorn_installed() -> bool:
    """Check if uvicorn is installed."""
    try:
        import uvicorn
        return True
    except ImportError:
        return False


def check_fastapi_installed() -> bool:
    """Check if FastAPI is installed."""
    try:
        import fastapi
        return True
    except ImportError:
        return False


@click.command()
@click.option(
    '--host',
    default='0.0.0.0',
    help='Host to bind to (default: 0.0.0.0)',
    show_default=True
)
@click.option(
    '--port',
    default=8000,
    type=int,
    help='Port to bind to (default: 8000)',
    show_default=True
)
@click.option(
    '--reload',
    is_flag=True,
    help='Enable auto-reload for development'
)
@click.option(
    '--no-access-log',
    is_flag=True,
    help='Disable access logs'
)
def serve(host, port, reload, no_access_log):
    """
    Start the Secrets Sentry web dashboard.

    The dashboard provides a web interface to view findings, manage configuration,
    and track remediation progress.

    Examples:

        # Start with defaults
        python -m scripts.serve

        # Custom host and port
        python -m scripts.serve --host 127.0.0.1 --port 3000

        # Development mode with auto-reload
        python -m scripts.serve --reload
    """
    try:
        # Check dependencies
        if not check_fastapi_installed():
            console.print()
            console.print("[red]Error:[/red] FastAPI is not installed")
            console.print("[dim]Install with: pip install fastapi[/dim]")
            console.print()
            sys.exit(1)

        if not check_uvicorn_installed():
            console.print()
            console.print("[red]Error:[/red] Uvicorn is not installed")
            console.print("[dim]Install with: pip install uvicorn[standard][/dim]")
            console.print()
            sys.exit(1)

        # Import after checking dependencies
        import uvicorn

        # Display startup message
        console.print()

        # Get local IP for display
        local_ip = get_local_ip()

        # Create info panel
        info_lines = []
        info_lines.append(f"[bold cyan]Local:[/bold cyan]   http://localhost:{port}")
        if host == '0.0.0.0' and local_ip != "127.0.0.1":
            info_lines.append(f"[bold cyan]Network:[/bold cyan] http://{local_ip}:{port}")
        info_lines.append("")
        info_lines.append("[dim]Press CTRL+C to stop[/dim]")

        if reload:
            info_lines.append("[yellow]⚡ Auto-reload enabled[/yellow]")

        console.print(Panel(
            "\n".join(info_lines),
            title="🚀 Starting Secrets Sentry Dashboard",
            border_style="green",
            box=box.ROUNDED
        ))
        console.print()

        # Try to import the app
        try:
            # Check if there's a FastAPI app in src/api
            from src.api import app as api_app

            if hasattr(api_app, 'app'):
                app = api_app.app
            elif callable(api_app):
                app = api_app
            else:
                # Create a basic app
                app = create_basic_app()
        except (ImportError, AttributeError):
            # Create a basic app if none exists
            app = create_basic_app()

        # Start server
        uvicorn.run(
            app,
            host=host,
            port=port,
            reload=reload,
            access_log=not no_access_log,
            log_level="info"
        )

    except KeyboardInterrupt:
        console.print("\n[yellow]Server stopped by user.[/yellow]")
        sys.exit(0)
    except OSError as e:
        if "Address already in use" in str(e):
            console.print()
            console.print(f"[red]Error:[/red] Port {port} is already in use")
            console.print(f"[dim]Try a different port: python -m scripts.serve --port {port + 1}[/dim]")
            console.print()
        else:
            console.print(f"\n[red]Error:[/red] {e}")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[red]Error:[/red] {e}")
        import traceback
        console.print(f"[dim]{traceback.format_exc()}[/dim]")
        sys.exit(1)


def create_basic_app():
    """Create a basic FastAPI app if none exists."""
    from fastapi import FastAPI
    from fastapi.responses import HTMLResponse, JSONResponse
    from fastapi.staticfiles import StaticFiles
    from pathlib import Path

    from src.utils.storage import load_findings
    from src.utils.config import load_settings

    app = FastAPI(
        title="Secrets Sentry Dashboard",
        description="Monitor and manage secret detection findings",
        version="1.0.0"
    )

    @app.get("/", response_class=HTMLResponse)
    async def home():
        """Home page with dashboard."""
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Secrets Sentry Dashboard</title>
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body {
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    min-height: 100vh;
                    padding: 2rem;
                }
                .container {
                    max-width: 1200px;
                    margin: 0 auto;
                    background: white;
                    border-radius: 1rem;
                    padding: 2rem;
                    box-shadow: 0 20px 60px rgba(0,0,0,0.3);
                }
                h1 {
                    color: #667eea;
                    margin-bottom: 0.5rem;
                    font-size: 2.5rem;
                }
                .subtitle {
                    color: #666;
                    margin-bottom: 2rem;
                }
                .stats {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                    gap: 1rem;
                    margin-bottom: 2rem;
                }
                .stat-card {
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 1.5rem;
                    border-radius: 0.5rem;
                    box-shadow: 0 4px 12px rgba(0,0,0,0.1);
                }
                .stat-card h3 {
                    font-size: 0.875rem;
                    text-transform: uppercase;
                    opacity: 0.9;
                    margin-bottom: 0.5rem;
                }
                .stat-card .value {
                    font-size: 2.5rem;
                    font-weight: bold;
                }
                .links {
                    display: flex;
                    gap: 1rem;
                    flex-wrap: wrap;
                }
                .btn {
                    background: #667eea;
                    color: white;
                    padding: 0.75rem 1.5rem;
                    border-radius: 0.5rem;
                    text-decoration: none;
                    transition: all 0.2s;
                    display: inline-block;
                }
                .btn:hover {
                    background: #5568d3;
                    transform: translateY(-2px);
                    box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4);
                }
                .endpoint {
                    background: #f7fafc;
                    padding: 1rem;
                    border-radius: 0.5rem;
                    margin: 0.5rem 0;
                    font-family: 'Monaco', monospace;
                    font-size: 0.875rem;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🔐 Secrets Sentry</h1>
                <p class="subtitle">Dashboard is running</p>

                <div class="stats" id="stats">
                    <div class="stat-card">
                        <h3>Status</h3>
                        <div class="value">✓ Active</div>
                    </div>
                    <div class="stat-card">
                        <h3>Total Findings</h3>
                        <div class="value" id="findings-count">-</div>
                    </div>
                </div>

                <h2 style="margin-bottom: 1rem;">API Endpoints</h2>
                <div class="endpoint">GET /api/findings - List all findings</div>
                <div class="endpoint">GET /api/stats - Get statistics</div>
                <div class="endpoint">GET /api/health - Health check</div>

                <div style="margin-top: 2rem;">
                    <div class="links">
                        <a href="/api/findings" class="btn">View Findings (JSON)</a>
                        <a href="/api/stats" class="btn">View Stats (JSON)</a>
                        <a href="/docs" class="btn">API Documentation</a>
                    </div>
                </div>
            </div>

            <script>
                // Fetch and display findings count
                fetch('/api/findings')
                    .then(r => r.json())
                    .then(data => {
                        document.getElementById('findings-count').textContent =
                            data.findings ? data.findings.length : 0;
                    })
                    .catch(e => {
                        document.getElementById('findings-count').textContent = 'Error';
                    });
            </script>
        </body>
        </html>
        """

    @app.get("/api/health")
    async def health():
        """Health check endpoint."""
        return {"status": "healthy", "service": "secrets-sentry"}

    @app.get("/api/findings")
    async def get_findings():
        """Get all findings."""
        try:
            settings = load_settings()
            findings = load_findings(settings.data_dir)
            return {"findings": findings, "count": len(findings)}
        except Exception as e:
            return JSONResponse(
                status_code=500,
                content={"error": str(e)}
            )

    @app.get("/api/stats")
    async def get_stats():
        """Get statistics."""
        try:
            settings = load_settings()
            findings = load_findings(settings.data_dir)

            high = sum(1 for f in findings if f.get('confidence', 0) >= 0.8)
            medium = sum(1 for f in findings if 0.5 <= f.get('confidence', 0) < 0.8)
            low = sum(1 for f in findings if f.get('confidence', 0) < 0.5)

            return {
                "total": len(findings),
                "by_confidence": {
                    "high": high,
                    "medium": medium,
                    "low": low
                },
                "files_affected": len(set(f.get('file', '') for f in findings))
            }
        except Exception as e:
            return JSONResponse(
                status_code=500,
                content={"error": str(e)}
            )

    return app


if __name__ == "__main__":
    serve()
