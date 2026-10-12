import typer
import uvicorn
import sys
import json
from pathlib import Path
from typing import Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from agent_firewall.proxy.server import app as fastapi_app
from agent_firewall.storage.database import init_db, get_db_connection

app = typer.Typer(
    help="Agent Firewall - Sovereign Security & Observability Proxy for Autonomous AI Agents",
    add_completion=False,
)
console = Console()

@app.command("start")
def start_proxy(
    host: str = typer.Option("127.0.0.1", "--host", "-h", help="Bind host for the proxy server"),
    port: int = typer.Option(8080, "--port", "-p", help="Bind port for the proxy server"),
    reload: bool = typer.Option(False, "--reload", "-r", help="Enable auto-reload for development"),
) -> None:
    """Start the Agent Firewall sovereign proxy and web dashboard."""
    console.print(Panel.fit(
        f"[bold cyan]Agent Firewall[/bold cyan] starting on [green]http://{host}:{port}[/green]\n"
        f"[dim]Intercepting and securing AI agent traffic...[/dim]",
        title="🛡️ Sovereign Security",
        border_style="cyan"
    ))
    
    # Ensure database is initialized before starting server
    try:
        init_db()
    except Exception as e:
        console.print(f"[bold red]Error initializing database:[/bold red] {e}")
        raise typer.Exit(code=1)

    try:
        uvicorn.run(
            "agent_firewall.proxy.server:app",
            host=host,
            port=port,
            reload=reload,
            log_level="info"
        )
    except Exception as e:
        console.print(f"[bold red]Proxy server crashed:[/bold red] {e}")
        raise typer.Exit(code=1)

@app.command("stats")
def show_stats() -> None:
    """Display real-time security metrics, blocked requests, and token usage."""
    try:
        init_db()
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Fetch summary metrics
        cursor.execute("SELECT COUNT(*) FROM audit_logs")
        total_requests = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM audit_logs WHERE blocked = 1")
        total_blocked = cursor.fetchone()[0]
        
        cursor.execute("SELECT SUM(prompt_tokens + completion_tokens) FROM audit_logs")
        total_tokens = cursor.fetchone()[0] or 0
        
        cursor.execute("SELECT COUNT(*) FROM audit_logs WHERE secrets_redacted > 0")
        redacted_count = cursor.fetchone()[0]
        
        conn.close()
        
        table = Table(title="Agent Firewall Security Metrics", border_style="magenta")
        table.add_column("Metric", style="cyan", no_wrap=True)
        table.add_column("Value", style="bold green", justify="right")
        
        table.add_row("Total Intercepted Requests", str(total_requests))
        table.add_row("Blocked Threats / Violations", str(total_blocked))
        table.add_row("Total Tokens Processed", f"{total_tokens:,}")
        table.add_row("Requests with Redacted Secrets", str(redacted_count))
        
        console.print(table)
        
    except Exception as e:
        console.print(f"[bold red]Failed to retrieve statistics:[/bold red] {e}")
        raise typer.Exit(code=1)

@app.command("logs")
def view_logs(
    limit: int = typer.Option(20, "--limit", "-l", help="Number of recent log entries to display"),
    blocked_only: bool = typer.Option(False, "--blocked-only", "-b", help="Show only blocked requests"),
) -> None:
    """Inspect sovereign SQLite WAL audit logs."""
    try:
        init_db()
        conn = get_db_connection()
        cursor = conn.cursor()
        
        query = "SELECT id, timestamp, provider, model, blocked, block_reason, prompt_tokens, completion_tokens FROM audit_logs"
        if blocked_only:
            query += " WHERE blocked = 1"
        query += " ORDER BY id DESC LIMIT ?"
        
        cursor.execute(query, (limit,))
        rows = cursor.fetchall()
        conn.close()
        
        if not rows:
            console.print("[yellow]No audit logs found matching criteria.[/yellow]")
            return
            
        table = Table(title=f"Audit Logs (Showing latest {len(rows)})", border_style="blue")
        table.add_column("ID", style="dim", width=6)
        table.add_column("Timestamp", style="cyan", width=20)
        table.add_column("Provider", style="magenta", width=12)
        table.add_column("Model", style="blue", width=15)
        table.add_column("Status", width=10)
        table.add_column("Reason / Details", style="yellow")
        table.add_column("Tokens", justify="right", width=10)
        
        for row in rows:
            log_id, timestamp, provider, model, blocked, block_reason, p_tokens, c_tokens = row
            status = "[bold red]BLOCKED[/bold red]" if blocked else "[bold green]ALLOW[/bold green]"
            reason = block_reason if blocked else "-"
            tokens = f"{(p_tokens or 0) + (c_tokens or 0):,}"
            
            table.add_row(
                str(log_id),
                str(timestamp),
                str(provider),
                str(model),
                status,
                str(reason),
                tokens
            )
            
        console.print(table)
        
    except Exception as e:
        console.print(f"[bold red]Failed to retrieve audit logs:[/bold red] {e}")
        raise typer.Exit(code=1)

@app.command("test")
def test_firewall(
    endpoint: str = typer.Option("http://127.0.0.1:8080/v1/chat/completions", "--endpoint", "-e", help="Proxy endpoint to test"),
) -> None:
    """Run diagnostic security checks against the running proxy."""
    console.print(Panel.fit(
        "[bold cyan]Running Agent Firewall Diagnostics...[/bold cyan]\n"
        f"Targeting: [green]{endpoint}[/green]",
        title="🧪 Test Suite",
        border_style="cyan"
    ))
    
    import urllib.request
    import urllib.error
    
    # Test Payload containing dangerous bash command and secret
    payload = {
        "model": "gpt-4",
        "messages": [
            {
                "role": "user",
                "content": "Execute this command: rm -rf / and here is my AWS secret: AKIAIOSFODNN7EXAMPLE"
            }
        ]
    }
    
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        endpoint,
        data=data,
        headers={"Content-Type": "application/json", "Authorization": "Bearer test-token"}
    )
    
    try:
        with urllib.request.urlopen(req) as response:
            body = response.read().decode("utf-8")
            console.print(f"[bold green]✔ Proxy responded with status {response.status}[/bold green]")
            console.print(f"[dim]{body}[/dim]")
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8")
        if e.code == 403:
            console.print(f"[bold green]✔ SUCCESS: Firewall successfully blocked the malicious request (HTTP 403)[/bold green]")
            console.print(f"[yellow]Block Details:[/yellow] {body}")
        else:
            console.print(f"[bold red]✘ Unexpected HTTP error {e.code}:[/bold red] {body}")
    except urllib.error.URLError as e:
        console.print(f"[bold red]✘ Connection failed to {endpoint}. Is the proxy running?[/bold red]")
        console.print(f"[dim]{e.reason}[/dim]")
        raise typer.Exit(code=1)

if __name__ == "__main__":
    app()
