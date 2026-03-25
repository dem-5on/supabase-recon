import asyncio
from enum import Enum
from pathlib import Path
from typing import Optional
import aiohttp
import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from .scanner import SupabaseScanner
from .reporter import print_result, print_summary, save_json

app = typer.Typer(
    name="supabase-recon",
    help="Passive & deep Supabase recon for authorized bug bounty research.",
    add_completion=False,
    rich_markup_mode="rich",
)

console = Console()
__version__ = "1.1.0"


class ScanMode(str, Enum):
    passive = "passive"
    deep    = "deep"


def version_callback(value: bool):
    if value:
        typer.echo(f"supabase-recon {__version__}")
        raise typer.Exit()


def load_targets(file: Path) -> list[str]:
    lines = file.read_text().splitlines()
    return [l.strip() for l in lines if l.strip() and not l.strip().startswith("#")]


def confirm_deep_mode(targets: list[str]) -> bool:
    console.print(
        Panel(
            "[bold red]DEEP MODE WARNING[/bold red]\n\n"
            "Deep mode uses any exposed JWT found during passive scanning to:\n"
            "  • Enumerate tables via the Supabase REST API\n"
            "  • Read rows from accessible tables (paginated)\n"
            "  • Analyse retrieved data for sensitive fields\n"
            "  • Save raw table dumps to disk under [bold]./output/[/bold]\n\n"
            "[yellow]Only proceed on targets you have explicit written authorization to test.[/yellow]\n"
            "Unauthorized access to computer systems is illegal in most jurisdictions.",
            border_style="red",
            expand=False,
        )
    )
    console.print(f"  Targets queued: [bold]{len(targets)}[/bold]\n")
    answer = typer.prompt('Type "I have authorization" to continue, or anything else to cancel')
    return answer.strip() == "I have authorization"


async def _run(targets, mode, output, output_dir, concurrency, timeout, max_js, verbose):
    deep = mode == ScanMode.deep
    scanner = SupabaseScanner(timeout=timeout, max_js=max_js)
    connector = aiohttp.TCPConnector(limit=concurrency, ssl=False)
    ua = "Mozilla/5.0 (compatible; security-recon-tool/1.0)"
    sem = asyncio.Semaphore(concurrency)

    async with aiohttp.ClientSession(connector=connector, headers={"User-Agent": ua}) as session:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
            transient=True,
        ) as progress:
            label = "deep" if deep else "passive"
            task = progress.add_task(f"Scanning [{label}]…", total=len(targets))

            async def guarded(t):
                async with sem:
                    result = await scanner.scan(session, t, deep=deep, output_dir=output_dir)
                    progress.advance(task)
                    if verbose or result.supabase_detected:
                        print_result(result)
                    return result

            results = await asyncio.gather(*[guarded(t) for t in targets])

    if not verbose:
        for r in results:
            if not r.supabase_detected:
                print_result(r)

    print_summary(list(results))
    if output:
        save_json(list(results), output)


@app.command()
def scan(
    target: Optional[str] = typer.Option(None, "--target", "-t", help="Single target URL.", metavar="URL"),
    file: Optional[Path] = typer.Option(
        None, "--file", "-f", help="File with one URL per line.",
        metavar="FILE", exists=True, file_okay=True, readable=True,
    ),
    mode: ScanMode = typer.Option(
        ScanMode.passive, "--mode", "-m",
        help="[bold]passive[/bold] — HTML/JS only (default).  [bold]deep[/bold] — enumerate + dump tables via exposed JWT.",
        show_default=True,
    ),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save JSON report.", metavar="FILE"),
    output_dir: str = typer.Option("output", "--output-dir", help="Dir for deep-mode table dumps.", metavar="DIR"),
    concurrency: int = typer.Option(10, "--concurrency", "-c", help="Max concurrent requests.", min=1, max=50),
    timeout: int = typer.Option(15, "--timeout", help="Per-request timeout (seconds).", min=5),
    max_js: int = typer.Option(30, "--max-js", help="Max JS files per target.", min=1),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Print results as they complete."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip deep-mode confirmation prompt."),
    version: Optional[bool] = typer.Option(None, "--version", callback=version_callback, is_eager=True),
):
    """
    Scan targets for exposed Supabase credentials.

    \b
    Modes:
      passive  Crawls HTML + JS assets only. No API calls. (default)
      deep     After passive detection, uses the exposed JWT to enumerate tables,
               read accessible rows, and flag sensitive fields.
               Requires explicit confirmation — authorized use only.

    \b
    Examples:
      supabase-recon --target https://example.com
      supabase-recon --file targets.txt --output report.json
      supabase-recon --file targets.txt --mode deep
      supabase-recon --target https://example.com --mode deep --yes
    """
    if not target and not file:
        console.print("[red]Error:[/red] Provide --target or --file.")
        raise typer.Exit(1)

    targets: list[str] = []
    if target:
        targets.append(target)
    if file:
        targets.extend(load_targets(file))

    if not targets:
        console.print("[red]Error:[/red] No valid targets found.")
        raise typer.Exit(1)

    if mode == ScanMode.deep and not yes:
        if not confirm_deep_mode(targets):
            console.print("\n[yellow]Cancelled.[/yellow]")
            raise typer.Exit(0)

    mode_badge = "[red]deep[/red]" if mode == ScanMode.deep else "[cyan]passive[/cyan]"
    console.print(
        f"\n[bold cyan]supabase-recon[/bold cyan] [dim]v{__version__}[/dim]  "
        f"│  mode: {mode_badge}  "
        f"│  targets: [bold]{len(targets)}[/bold]  "
        f"│  concurrency: [bold]{concurrency}[/bold]"
    )

    asyncio.run(_run(targets, mode, output, output_dir, concurrency, timeout, max_js, verbose))


def main():
    app()