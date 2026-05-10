"""Executive report workspace chrome HTML helpers."""
# ruff: noqa: F401,F403,F405,I001,E501

from __future__ import annotations

from html import escape
from typing import Any

from vuln_prioritizer.reporting_executive_utils import (
    _text,
)


def _workspace_app_header_html() -> str:
    return (
        '<header class="er-app-header">'
        '<a class="er-app-brand" href="/">'
        f'<span class="er-app-brand-logo">{_shield_logo_svg()}</span>'
        "<span>Vuln Prioritizer Workbench</span></a></header>"
    )


def _workspace_nav_html(nav: Any, *, interactive: bool = False) -> str:
    if not isinstance(nav, dict):
        return ""
    groups = nav.get("groups")
    if not isinstance(groups, list):
        return ""
    group_html: list[str] = []
    for group in groups:
        if not isinstance(group, dict):
            continue
        links = group.get("links")
        if not isinstance(links, list):
            continue
        link_html = []
        for link in links:
            if not isinstance(link, dict):
                continue
            label = _text(link.get("label"))
            href = _text(link.get("href"), default="#")
            active = ' aria-current="page"' if link.get("active") else ""
            link_html.append(
                f'<a href="{escape(href)}" title="{escape(label)}"{active}>'
                '<span class="nav-icon" aria-hidden="true">'
                f"{_workspace_nav_icon(label)}</span>"
                f'<span class="nav-label">{escape(label)}</span></a>'
            )
        group_html.append(
            '<div class="er-workspace-nav-group side-nav-group">'
            f"<p>{escape(_text(group.get('label')))}</p>" + "".join(link_html) + "</div>"
        )
    if not group_html:
        return ""
    toggle = (
        '<button class="sidebar-toggle" type="button" data-sidebar-toggle '
        'aria-label="Collapse navigation" aria-pressed="false">'
        '<span class="sidebar-toggle-icon" aria-hidden="true"></span>'
        '<span class="sidebar-toggle-text">Collapse</span></button>'
        if interactive
        else ""
    )
    return (
        '<aside class="er-workspace-sidebar app-sidebar" aria-label="Project navigation">'
        f"{toggle}"
        '<div class="er-workspace-project sidebar-project">'
        f'<span class="project-emblem" aria-hidden="true">{_shield_logo_svg()}</span>'
        '<span class="project-copy"><span>Project</span>'
        f"<strong>{escape(_text(nav.get('project')))}</strong></span></div>"
        '<nav class="er-workspace-nav side-nav">' + "".join(group_html) + "</nav></aside>"
    )


def _nav_link(item: dict[str, str]) -> str:
    return f'<a href="#{escape(item["id"])}">{escape(item["label"])}</a>'


def _shield_logo_svg() -> str:
    return (
        '<svg class="shield-logo" viewBox="0 0 48 56" focusable="false" aria-hidden="true">'
        '<path class="shield-logo-fill" '
        'd="M24 3 43 10.2v15.3c0 12.3-7.6 21.7-19 26.5C12.6 47.2 5 37.8 5 25.5V10.2L24 3z"/>'
        '<path class="shield-logo-check" d="m15.2 28.2 6.1 6.1 12.8-14.1"/>'
        "</svg>"
    )


def _workspace_nav_icon(label: str) -> str:
    icon_name = {
        "dashboard": "dashboard",
        "import": "import",
        "findings": "findings",
        "intelligence": "intelligence",
        "governance": "governance",
        "assets": "assets",
        "waivers": "waivers",
        "coverage": "coverage",
        "run artifacts": "artifacts",
        "executive report": "report",
        "settings": "settings",
    }.get(label.strip().lower(), "dashboard")
    return _nav_icon_svg(icon_name)


def _nav_icon_svg(name: str) -> str:
    paths = {
        "dashboard": "M4 4h7v7H4V4zm9 0h7v7h-7V4zM4 13h7v7H4v-7zm9 0h7v7h-7v-7z",
        "import": "M11 4h2v8l3-3 1.4 1.4L12 15.8l-5.4-5.4L8 9l3 3V4zM5 18h14v2H5v-2z",
        "findings": "M5 5h14v2H5V5zm0 6h14v2H5v-2zm0 6h10v2H5v-2z",
        "intelligence": (
            "M10.5 4a6.5 6.5 0 014.9 10.8l4.4 4.4-1.4 1.4-4.4-4.4"
            "A6.5 6.5 0 1110.5 4zm0 2a4.5 4.5 0 100 9 4.5 4.5 0 000-9z"
        ),
        "governance": (
            "M12 3l7 3v6c0 4-2.8 7.2-7 9-4.2-1.8-7-5-7-9V6l7-3zm-1 5v5l4 2 .9-1.8-2.9-1.4V8h-2z"
        ),
        "assets": "M4 5h16v5H4V5zm2 2v1h2V7H6zm-2 5h16v7H4v-7zm2 2v3h12v-3H6z",
        "waivers": (
            "M12 3a9 9 0 100 18 9 9 0 000-18zm4.7 7.7-5.4 5.4-3-3 1.4-1.4 1.6 1.6 4-4 1.4 1.4z"
        ),
        "coverage": (
            "M11 2h2v3.1A7 7 0 0118.9 11H22v2h-3.1A7 7 0 0113 18.9"
            "V22h-2v-3.1A7 7 0 015.1 13H2v-2h3.1A7 7 0 0111 5.1V2zm1 5"
            "a5 5 0 100 10 5 5 0 000-10zm0 3a2 2 0 110 4 2 2 0 010-4z"
        ),
        "artifacts": "M4 5h6l2 2h8v12H4V5zm2 4v8h12V9H6z",
        "report": "M6 3h9l3 3v15H6V3zm8 2v3h3l-3-3zM8 10h8v2H8v-2zm0 4h8v2H8v-2z",
        "settings": (
            "M13 2l.6 2.5a7.8 7.8 0 011.7.7l2.2-1.3 2 3.4-2 1.5"
            "c.1.4.1.8.1 1.2s0 .8-.1 1.2l2 1.5-2 3.4-2.2-1.3"
            "c-.5.3-1.1.5-1.7.7L13 22h-4l-.6-2.5a7.8 7.8 0 01-1.7-.7"
            "l-2.2 1.3-2-3.4 2-1.5A8 8 0 014.4 14c0-.4 0-.8.1-1.2"
            "l-2-1.5 2-3.4 2.2 1.3c.5-.3 1.1-.5 1.7-.7L9 2h4zm-2 7"
            "a3 3 0 100 6 3 3 0 000-6z"
        ),
    }
    return f'<svg viewBox="0 0 24 24" focusable="false"><path d="{paths[name]}"/></svg>'


__all__ = [
    "_nav_icon_svg",
    "_nav_link",
    "_shield_logo_svg",
    "_workspace_app_header_html",
    "_workspace_nav_html",
    "_workspace_nav_icon",
]
