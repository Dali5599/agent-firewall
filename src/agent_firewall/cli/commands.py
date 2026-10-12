import asyncio
import json
import sqlite3
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.live import Live
from rich.layout import Layout

from agent_firewall.proxy.server import run_server
from agent_firewall.audit.db import init_db, get_db_path
from agent_firewall.core.config import get_settings
from agent_firewall.simulation.runner import run_simulation_tests

app = typer.Typer(help="Agent Firewall - Sovereign Security & Observability Proxy")
console = Console()

@app.command("start")
def start(
    host: str = typer.Option("127.0.0.1", "--host", "-h", help="Bind host for the proxy server"),
    port: int = typer.Option(8080, "--port", "-p", help="Bind port for the proxy server"),
    workers: int = typer.Option(1, "--workers", "-w", help="Number of worker processes"),
) -> None:
    """
    Start the Agent Firewall sovereign proxy server.
    """
    settings = get_settings()
    init_db()

    console.print(
        Panel.fit(
            f"[bold cyan]Agent Firewall Proxy[/bold cyan]\n\n"
            f"🚀 Starting sovereign proxy on [green]http://{host}:{port}[/green]\n"
            f"🔒 Mode: Enterprise Security & Observability\n"
            f"📦 Audit DB: {get_db_path()}",
            title="[bold blue]SOVEREIGN SECURITY[/bold blue]",
            border_color="cyan",
        )
    )

    try:
        run_server(host=host, port=port, workers=workers)
    except KeyboardInterrupt:
        console.print("\n[yellow]Shutting down Agent Firewall gracefully...[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[bold red]Error running proxy server:[/bold red] {e}")
        sys.exit(1)

@app.command("stats")
def stats() -> None:
    """
    Display real-time security telemetry and token budget statistics.
    """
    db_path = get_db_path()
    if not db_path.exists():
        console.print("[yellow]No audit database found yet. Start the proxy and run some requests first.[/yellow]")
        return

    try:
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM requests")
        total_requests = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM requests WHERE blocked = 1")
        blocked_requests = cursor.fetchone()[0]

        cursor.execute("SELECT SUM(prompt_tokens + completion_tokens) FROM requests")
        total_tokens = cursor.fetchone()[0] or 0

        cursor.execute("SELECT SUM(cost_usd) FROM requests")
        total_cost = cursor.fetchone()[0] or 0.0

        cursor.execute("SELECT COUNT(*) FROM redactions")
        total_redactions = cursor.fetchone()[0]

        conn.close()

        table = Table(title="Agent Firewall Telemetry & Statistics", border_style="cyan")
        table.add_column("Metric", style="bold magenta", no_wrap=True)
        table.add_column("Value", style="bold green")

        table.add_row("Total API Requests", str(total_requests))
        table.add_row("Blocked Requests", str(blocked_requests))
        table.add_row("Total Redactions", str(total_redactions))
        table.add_row("Total Tokens Consumed", f"{total_tokens:,}")
        table.add_row("Estimated Cost (USD)", f"${total_cost:.4f}")

        console.print(table)

    except Exception as e:
        console.print(f"[bold red]Failed to retrieve statistics:[/bold red] {e}")
        sys.exit(1)

@app.command("logs")
def logs(
    limit: int = typer.Option(20, "--limit", "-l", help="Number of recent log entries to show"),
    follow: bool = typer.Option(False, "--follow", "-f", help="Stream audit logs in real-time"),
) -> None:
    """
    Tail sovereign SQLite WAL audit logs.
    """
    db_path = get_db_path()
    if not db_path.exists():
        console.print("[yellow]No audit logs found. Database has not been initialized.[/yellow]")
        return

    def fetch_logs(conn: sqlite3.connection, lim: int):
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, timestamp, provider, model, blocked, block_reason, prompt_tokens, completion_tokens, cost_usd
            FROM requests
            ORDER BY timestamp DESC
            LIMIT ?
            """,
            (lim,),
        )
        return cursor.fetchall()

    try:
        conn = sqlite3.connect(str(db_path))
        if not follow:
            rows = fetch_logs(conn, limit)
            table = Table(title=f"Recent Audit Logs (Last {limit})", border_style="blue")
            table.add_column("ID", style="dim")
            table.add_column("Timestamp", style="cyan")
            table.add_column("Provider", style="magenta")
            table.add_column("Model", style="blue")
            table.add_column("Status", style="bold")
            table.add_column("Tokens", style="yellow")
            table.add_column("Cost", style="green")

            for row in reversed(rows):
                req_id, ts, provider, model, blocked, reason, p_tok, c_tok, cost = row
                status = "[red]BLOCKED[/red]" if blocked else "[green]ALLOWED[/green]"
                if reason:
                    status += f" ({reason})"
                tokens = f"{(p_tok or 0) + (c_tok or 0)}"
                cost_str = f"${cost:.4f}" if cost is not None else "$0.0000"
                table.add_row(str(req_id), str(ts), str(provider), str(model), status, tokens, cost_str)

            console.print(table)
            conn.close()
        else:
            console.print("[cyan]Streaming audit logs in real-time (Ctrl+C to exit)...[/cyan]")
            seen_ids = set()
            while True:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT id, timestamp, provider, model, blocked, block_reason, prompt_tokens, completion_tokens, cost_usd
                    FROM requests
                    ORDER BY timestamp DESC
                    LIMIT 10
                    """
                )
                rows = cursor.fetchall()
                for row in rows:
                    req_id = row[0]
                    if req_id not in seen_ids:
                        seen_ids.add(req_id)
                        _, ts, provider, model, blocked, reason, p_tok, c_tok, cost = row
                        status = "BLOCKED" if blocked else "ALLOWED"
                        console.print(f"[dim]{ts}[/dim] | [magenta]{provider}[/magenta] | {model} | [{ 'red' if blocked else 'green' }]{status}[/] | Tokens: {(p_tok or 0) + (c_tok or 0)}")
                import time
                time.sleep(1.0)

    except KeyboardInterrupt:
        console.print("\n[yellow]Stopped logging stream.[/yellow]")
    except Exception as e:
        console.print(f"[bold red]Error reading audit logs:[/bold red] {e}")
        sys.exit(1)

@app.command("test")
def test_simulation() -> None:
    """
    Run built-in red-team simulation tests (prompt injection, PII leak, bash command block).
    """
    console.print(Panel.fit("[bold yellow]Running Agent Firewall Red-Team Simulation Suite[/bold yellow]", border_style="yellow"))
    
    try:
        results = run_simulation_tests()
        table = Table(title="Simulation Test Results", border_style="magenta")
        table.add_column("Test Case", style="bold cyan")
        table.add_column("Category", style="blue")
        table.add_column("Expected Outcome", style="dim")
        table.add_column("Result", style="bold")

        all_passed = True
        for test in results:
            passed = test["passed"]
            if not passed:
                all_passed = False
            res_str = "[green]PASSED[/green]" if passed else "[red]FAILED[/red]"
            table.add_row(test["name"], test["category"], test["expected"], res_str)

        console.print(table)

        if all_passed:
            console.print("\n[bold green]✨ All simulation security checks passed successfully![/bold green]")
        else:
            console.print("\n[bold red]⚠️ Some security simulation tests failed.[/bold red]")
            sys.exit(1)

    except Exception as e:
        console.print(f"[bold red]Simulation suite execution failed:[/bold red] {e}")
        sys.exit(1)
