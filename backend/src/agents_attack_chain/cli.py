import asyncio
import logging
from typing import Optional
import typer
from rich.console import Console
from rich.table import Table
from .services.attack_chain_service import AsyncDataManager
from .config.settings import settings

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
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
    
    async def _run():
        async with AsyncDataManager() as manager:
            stored_ids = await manager.process_attack_chains()
            
            console.print(f"\n[bold green]✓ Successfully processed {len(stored_ids)} attack chains[/bold green]")
            console.print(f"  • Stored in Elasticsearch index: {settings.get_target_index()}")
            console.print(f"  • Stored in Neo4j graph database")
            console.print(f"  • View chains in NeoDash: http://localhost:8080")
    
    asyncio.run(_run())

@app.command()
def sample():
    """Display a sample attack chain from Neo4j"""
    async def _run():
        async with AsyncDataManager() as manager:
            chain = await manager.get_sample_attack_chain()
            if not chain:
                console.print("[bold red]No attack chains found in Neo4j[/bold red]")
                return
            
            console.print(f"\n[bold blue]Sample Attack Chain: {chain['chainId']}[/bold blue]")
            console.print(f"Size: {chain['size']} events\n")
            
            table = Table(title="Log Events in Chain")
            table.add_column("Timestamp", style="cyan")
            table.add_column("Rule", style="magenta")
            table.add_column("Severity", style="yellow")
            table.add_column("Host", style="green")
            
            for event in chain['events']:
                host = event.get('host', {}).get('hostname', 'N/A') if event.get('host') else 'N/A'
                table.add_row(
                    event.get('timestamp', 'N/A')[:19],
                    event.get('ruleName', 'N/A')[:40],
                    event.get('severity', 'N/A').upper(),
                    host[:30]
                )
            
            console.print(table)
            console.print("\n[bold]View full chain in NeoDash:[/bold] http://localhost:8080")
    
    asyncio.run(_run())

@app.command()
def config():
    """Display current configuration"""
    table = Table(title="Project Configuration")
    table.add_column("Parameter", style="cyan")
    table.add_column("Value", style="green")
    
    table.add_row("Elasticsearch Host", settings.ELASTIC_HOST)
    table.add_row("Elasticsearch Index", settings.ELASTIC_INDEX_PATTERN)
    table.add_row("Target Index Prefix", settings.TARGET_INDEX_PREFIX)
    table.add_row("Neo4j URI", settings.NEO4J_URI)
    table.add_row("Time Range (GTE)", settings.TIME_RANGE_GTE)
    table.add_row("Time Range (LTE)", settings.TIME_RANGE_LTE)
    table.add_row("Min Risk Score", str(settings.MIN_RISK_SCORE))
    table.add_row("Max Chains", str(settings.MAX_CHAINS))
    table.add_row("Max Chain Size", str(settings.MAX_CHAIN_SIZE))
    table.add_row("SEPSes Base URI", settings.SEPSES_BASE_URI)
    
    console.print(table)

if __name__ == "__main__":
    app()