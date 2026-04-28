"""Workbench web command registrations."""

from __future__ import annotations

import typer
import uvicorn


def web_serve(
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(8000, "--port", min=1, max=65535),
    reload: bool = typer.Option(False, "--reload"),
) -> None:
    """Serve the Workbench web application."""
    uvicorn.run(
        "vuln_prioritizer.api.app:create_app",
        factory=True,
        host=host,
        port=port,
        reload=reload,
    )


def register(web_app: typer.Typer) -> None:
    web_app.command("serve")(web_serve)
