import asyncio
import logging
from typing import Optional
import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from .services.attack_chain_service import AsyncDataManager
from .config.settings import settings
from .db.schema import Neo4jSchemaManager

app = typer.Typer()
console = Console()

@app.command()
def process(
    time_gte: Optional[str] = typer.Option(None, "--from", help="Start time (e.g., 'now-24h')"),
    time_lte: Optional[str] = typer.Option(None, "--to", help="End time (e.g., 'now')"),
    min_risk: Optional[int] = typer.Option(None, "--min-risk", help="Minimum risk score"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose logging")
):
    """Extract, transform, and store attack chains from Elasticsearch to Neo4j"""
    if verbose:
        logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
    else:
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    
    async def _run():
        async with AsyncDataManager() as manager:
            stored_ids = await manager.process_attack_chains()
            
            console.print(Panel.fit(
                f"[bold green]✓ Successfully processed {len(stored_ids)} attack chains[/bold green]\n"
                f"  • Stored in Elasticsearch: [cyan]{settings.get_target_index()}[/cyan]\n"
                f"  • Stored in Neo4j graph database\n"
                f"  • View chains in NeoDash: [link=http://185.130.79.32:8080]http://185.130.79.32:8080[/link]",
                title="Processing Complete",
                border_style="green"
            ))
    
    asyncio.run(_run())

@app.command()
def sample():
    """Display a sample attack chain from Neo4j"""
    async def _run():
        async with AsyncDataManager() as manager:
            chain = await manager.get_sample_attack_chain()
            if not chain:
                console.print("[bold red]❌ No attack chains found in Neo4j[/bold red]")
                console.print("💡 Try running: [bold]attack-chain process --min-risk 30[/bold]")
                return
            
            console.print(f"\n[bold blue]📊 Sample Attack Chain: {chain['chainId']}[/bold blue]")
            console.print(f"Size: [bold]{chain['size']}[/bold] events | "
                         f"Time range: {chain['firstTimestamp'][:19]} → {chain['lastTimestamp'][:19]}")
            
            table = Table(title="Log Events in Chain (Chronological Order)", show_lines=True)
            table.add_column("#", style="cyan", justify="right", width=3)
            table.add_column("Timestamp", style="yellow", width=20)
            table.add_column("Rule", style="magenta", width=30)
            table.add_column("Severity", style="red", justify="center", width=10)
            table.add_column("Host", style="green", width=15)
            table.add_column("TTP", style="blue", width=25)
            
            for idx, event in enumerate(chain['events'], 1):
                severity_style = {
                    "critical": "[bold red]CRITICAL[/bold red]",
                    "high": "[red]HIGH[/red]",
                    "medium": "[yellow]MEDIUM[/yellow]",
                    "low": "[green]LOW[/green]"
                }.get(event.get('severity', 'low').lower(), event.get('severity', 'N/A'))
                
                ttp_display = f"{event.get('tactic', 'N/A')} → {event.get('technique', 'N/A')}"[:25]
                
                table.add_row(
                    str(idx),
                    event.get('timestamp', 'N/A')[11:19],  # فقط زمان
                    event.get('ruleName', 'N/A')[:28],
                    severity_style,
                    event.get('hostname', 'N/A')[:15],
                    ttp_display
                )
            
            console.print(table)
            console.print("\n[bold]💡 Interactive visualization:[/bold] [link=http://185.130.79.32:8080]http://185.130.79.32:8080[/link]")
    
    asyncio.run(_run())

@app.command()
def config():
    """Display current configuration"""
    table = Table(title="Project Configuration", show_lines=True)
    table.add_column("Category", style="bold blue")
    table.add_column("Parameter", style="cyan")
    table.add_column("Value", style="green")
    
    # Elasticsearch
    table.add_row("Elasticsearch", "Host", settings.ELASTIC_HOST)
    table.add_row("", "Index Pattern", settings.ELASTIC_INDEX_PATTERN)
    table.add_row("", "Target Index", settings.get_target_index())
    
    # Neo4j
    table.add_row("Neo4j", "URI", settings.NEO4J_URI)
    table.add_row("", "User", settings.NEO4J_USER)
    
    # Query Parameters
    table.add_row("Query", "Time Range", f"{settings.TIME_RANGE_GTE} → {settings.TIME_RANGE_LTE}")
    table.add_row("", "Min Risk Score", str(settings.MIN_RISK_SCORE))
    table.add_row("", "Max Chains", str(settings.MAX_CHAINS))
    table.add_row("", "Max Chain Size", str(settings.MAX_CHAIN_SIZE))
    
    # SEPSes
    table.add_row("SEPSes", "Base URI", settings.SEPSES_BASE_URI)
    
    console.print(table)

@app.command()
def schema(
    action: str = typer.Argument("status", help="Action: status, init"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show detailed schema information")
):
    """
    Manage Neo4j database schema (indexes and constraints for SEPSes ontology)
    
    Actions:
      status  Show current schema status (default)
      init    Initialize schema (idempotent - safe to run multiple times)
    """
    
    async def _run():
        async with AsyncDataManager() as manager:
            if action == "status":
                status = await manager.get_schema_status()
                
                if status.get("status") == "error":
                    console.print(f"[bold red]❌ Schema check failed:[/bold red] {status.get('error')}")
                    return
                
                console.print(Panel.fit(
                    f"[bold]Neo4j Schema Status[/bold]\n"
                    f"Indexes: {status['total_indexes']}/{status['expected_indexes']} ✅\n"
                    f"Constraints: {status['total_constraints']}/{status['expected_constraints']} ✅",
                    title="Schema Health",
                    border_style="green" if status['total_indexes'] >= status['expected_indexes'] and 
                                      status['total_constraints'] >= status['expected_constraints'] else "yellow"
                ))
                
                if verbose:
                    console.print("\n[bold blue]Detailed Indexes:[/bold blue]")
                    idx_table = Table(show_header=True, header_style="bold magenta")
                    idx_table.add_column("Name", style="cyan")
                    idx_table.add_column("Label", style="green")
                    idx_table.add_column("Property", style="yellow")
                    for idx in status['indexes']:
                        idx_table.add_row(idx['name'], idx['label'], idx['property'])
                    console.print(idx_table)
                    
                    console.print("\n[bold blue]Detailed Constraints:[/bold blue]")
                    con_table = Table(show_header=True, header_style="bold magenta")
                    con_table.add_column("Name", style="cyan")
                    con_table.add_column("Label", style="green")
                    con_table.add_column("Property", style="yellow")
                    for con in status['constraints']:
                        con_table.add_row(con['name'], con['label'], con['property'])
                    console.print(con_table)
            
            elif action == "init":
                console.print("[bold blue]🔧 Initializing Neo4j schema...[/bold blue]")
                result = await Neo4jSchemaManager.initialize_schema(manager.neo4j_client)
                console.print(Panel.fit(
                    f"[bold green]✅ Schema initialization complete![/bold green]\n"
                    f"  • Indexes created/verified: {result['indexes_created']}\n"
                    f"  • Constraints created/verified: {result['constraints_created']}",
                    title="Schema Initialization",
                    border_style="green"
                ))
            
            else:
                console.print(f"[bold red]❌ Unknown action: '{action}'[/bold red]")
                console.print("Available actions: [bold]status[/bold], [bold]init[/bold]")
    
    asyncio.run(_run())

if __name__ == "__main__":
    app()