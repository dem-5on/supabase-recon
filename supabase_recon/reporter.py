import json
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.text import Text
from rich.rule import Rule
from .models import TargetResult, Finding

console = Console()

SEV_STYLE: dict[str, str] = {
    "HIGH":   "bold red",
    "MEDIUM": "bold yellow",
    "LOW":    "bold blue",
    "INFO":   "bold cyan",
}

SEV_ICON: dict[str, str] = {
    "HIGH":   "🔴",
    "MEDIUM": "🟡",
    "LOW":    "🔵",
    "INFO":   "⚪",
}


def _finding_table(findings: list[Finding]) -> Table:
    table = Table(box=box.ROUNDED, show_header=True, header_style="bold white", expand=True)
    table.add_column("Sev", width=8)
    table.add_column("Type", width=16)
    table.add_column("Value")
    table.add_column("Source")

    for f in findings:
        sev = f.severity
        style = SEV_STYLE.get(sev, "")
        icon = SEV_ICON.get(sev, "")
        table.add_row(
            Text(f"{icon} {sev}", style=style),
            f.type,
            f.value,
            f.source,
        )

    return table


def _deep_scan_panel(deep: dict) -> None:
    """Render the deep scan table analysis below the passive panel."""
    from rich.table import Table as RTable
    from rich import box as rbox

    tables = deep.get("table_results", [])
    if not tables:
        console.print("  [dim]Deep scan: no accessible tables found.[/dim]")
        return

    accessible = [t for t in tables if t.get("accessible")]
    vulnerable  = [t for t in accessible if t.get("sensitive_fields")]

    console.print(
        f"\n  [bold white]Deep scan[/bold white]  │  "
        f"tables found: [bold]{deep.get('tables_found', 0)}[/bold]  │  "
        f"accessible: [bold]{deep.get('tables_accessible', 0)}[/bold]  │  "
        f"with sensitive data: [bold red]{len(vulnerable)}[/bold red]"
    )

    t = RTable(box=rbox.SIMPLE, show_header=True, header_style="bold white", expand=True)
    t.add_column("Table",       style="white")
    t.add_column("Rows",        justify="right", width=7)
    t.add_column("Status",      width=10)
    t.add_column("Risk",        width=10)
    t.add_column("Sensitive fields")

    LEVEL_STYLE = {
        "critical": "bold red",
        "high":     "bold yellow",
        "medium":   "yellow",
        "none":     "dim",
    }

    for row in tables:
        lvl   = row.get("vulnerability_level", "none")
        style = LEVEL_STYLE.get(lvl, "")
        sfields = ", ".join(row.get("sensitive_fields", [])) or "—"
        status = "✅" if row.get("accessible") else f"🔒 {row.get('http_status')}"
        t.add_row(
            row.get("table", ""),
            str(row.get("row_count", "—")),
            status,
            f"[{style}]{lvl.upper()}[/{style}]" if lvl != "none" else "[dim]none[/dim]",
            sfields,
        )

    console.print(t)

    # Show output directory hint
    if deep.get("tables_accessible", 0) > 0:
        console.print(
            f"  [dim]Raw table dumps saved to output/{deep.get('supabase_url','').split('//')[- 1].split('.')[0]}/tables/[/dim]"
        )


def print_result(result: TargetResult) -> None:
    status_icon = "✅" if result.reachable else "❌"
    detect_icon = "🔴 SUPABASE DETECTED" if result.supabase_detected else "⚪ Not detected"

    title = f"{status_icon}  {result.target}"
    subtitle = (
        f"{detect_icon}  │  "
        f"JS files: {len(result.js_files_scanned)}  │  "
        f"Findings: {len(result.findings)}"
    )

    border = "red" if result.supabase_detected else "dim"

    console.print()
    console.print(Panel(subtitle, title=title, border_style=border, expand=True))

    if result.errors:
        for e in result.errors:
            console.print(f"  [yellow]⚠  {e}[/yellow]")

    if result.findings:
        console.print(_finding_table(result.findings))

        # Detail snippets for HIGH findings
        high = [f for f in result.findings if f.severity == "HIGH" and f.context]
        if high:
            console.print("[dim]  Context snippets for HIGH findings:[/dim]")
            for f in high:
                console.print(f"  [red]{f.type}[/red] → ...{f.context[:160]}...")

    if result.deep_scan:
        _deep_scan_panel(result.deep_scan)


def print_summary(results: list[TargetResult]) -> None:
    console.print()
    console.print(Rule("[bold white]Summary[/bold white]"))

    total     = len(results)
    reachable = sum(1 for r in results if r.reachable)
    detected  = sum(1 for r in results if r.supabase_detected)
    high      = sum(
        1 for r in results for f in r.findings if f.severity == "HIGH"
    )

    table = Table(box=box.SIMPLE, show_header=False)
    table.add_column(style="dim", width=20)
    table.add_column(style="bold white")

    table.add_row("Targets scanned",  str(total))
    table.add_row("Reachable",         str(reachable))
    table.add_row("Supabase detected", f"[red]{detected}[/red]" if detected else "0")
    table.add_row("HIGH findings",     f"[red]{high}[/red]"     if high     else "0")

    console.print(table)


def save_json(results: list[TargetResult], path: str) -> None:
    data = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "total_targets": len(results),
        "supabase_detected": sum(1 for r in results if r.supabase_detected),
        "results": [r.to_dict() for r in results],
    }
    Path(path).write_text(json.dumps(data, indent=2))
    console.print(f"\n[green]✓[/green] JSON report saved → [bold]{path}[/bold]")