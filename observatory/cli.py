"""CLI entry point: `observatory run` (cron target) and `observatory show`."""

from __future__ import annotations

import json
from pathlib import Path

import typer

from technocore_mcp.client import TechnocoreClient, TechnocoreError
from technocore_mcp.identity import IdentityError

from observatory import collect, report

app = typer.Typer(add_completion=False, no_args_is_help=False)

REPO_ROOT = Path(__file__).resolve().parents[1]
REPORTS_DIR = REPO_ROOT / "reports"
STATE_PATH = REPO_ROOT / "state" / "api-baseline.json"
SUMMARY_PATH = REPO_ROOT / "reports" / "latest-summary.json"


@app.command()
def run(
    post: bool = typer.Option(
        False, "--post", help="publish signed digest + kv note to technocore.chat"
    ),
) -> None:
    client = TechnocoreClient()
    results: dict[str, dict] = {}
    failures = 0

    try:
        results["census"] = collect.census(client)
    except TechnocoreError as e:
        typer.echo(f"warning: census failed: {e}")
        results["census"] = {"error": str(e)}
        failures += 1

    try:
        results["duplicates"] = collect.duplicates(client)
    except TechnocoreError as e:
        typer.echo(f"warning: duplicates failed: {e}")
        results["duplicates"] = {"error": str(e)}
        failures += 1

    try:
        results["api"] = collect.api_surface(client, STATE_PATH)
    except TechnocoreError as e:
        typer.echo(f"warning: api_surface failed: {e}")
        results["api"] = {"error": str(e)}
        failures += 1

    try:
        results["health"] = collect.health(client)
    except TechnocoreError as e:
        typer.echo(f"warning: health failed: {e}")
        results["health"] = {"error": str(e)}
        failures += 1

    # Recount failures from the RESULTS, not just raised exceptions: health()
    # returns an error-dict instead of raising, so the exception counter alone
    # under-counted a total failure (review #4). A collector "failed" if its
    # result carries an error; health is fully-failed only when both probes are
    # None.
    def _failed(name: str) -> bool:
        r = results.get(name) or {}
        if name == "health":
            return "error" in r and r.get("healthz_ms") is None and r.get("read_ms") is None
        return "error" in r

    failures = sum(_failed(n) for n in ("census", "duplicates", "api", "health"))

    # Total collection failure: do NOT write a report, do NOT publish, do NOT
    # let the cron commit an empty artifact. Exit nonzero so the run registers
    # as the failure it is (adversarial review v3.0, serious #3).
    if failures == 4:
        typer.echo("all four collectors failed — no report written, nothing published")
        client.close()
        raise typer.Exit(code=1)

    summary = report.build_summary(
        results["census"], results["duplicates"], results["api"], results["health"]
    )

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    SUMMARY_PATH.write_text(json.dumps(summary, indent=1))
    report_path = REPORTS_DIR / f"{summary['date']}.md"
    report_path.write_text(report.render_report(summary))

    digest = report.render_digest(summary)
    typer.echo(digest)

    if post:
        try:
            r = client.say_signed("african-proofs", digest)
            typer.echo(f"posted digest: status={r.get('status')}")
        except IdentityError:
            typer.echo("no identity configured — skipping post")
        except TechnocoreError as e:
            typer.echo(f"warning: say_signed failed: {e}")

        note = report.render_note(summary)
        try:
            client.kv_set("observatory", summary["date"], note)
            client.kv_set("observatory", "latest", note)
            typer.echo("kv note written")
        except IdentityError:
            typer.echo("no identity configured — skipping post")
        except TechnocoreError as e:
            typer.echo(f"warning: kv_set failed: {e}")

    client.close()


@app.command()
def show() -> None:
    if not SUMMARY_PATH.exists():
        typer.echo("no summary yet — run `observatory run` first")
        raise typer.Exit(code=1)
    data = json.loads(SUMMARY_PATH.read_text())
    typer.echo(json.dumps(data, indent=1))


if __name__ == "__main__":
    app()
