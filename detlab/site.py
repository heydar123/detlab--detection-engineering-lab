"""A read-only copy of the lab as one static web page.

``python -m detlab export-site`` writes ``site/index.html``. It is the same page that ``python -m detlab app`` serves,
with every answer the server would give (the numbers, each alert's evidence, each case, the reports) embedded in it.
It needs no server and no internet connection, so it can be opened from a folder or published on GitHub Pages.

What the copy cannot do: generate new logs or test an edited rule, because that needs the lab running. The page turns
those controls off and says why.

Safety: the page ships with a Content-Security-Policy that allows no network access at all, and the embedded data is
written so that nothing inside it can end the script block (every "<", ">" and "&" becomes a \\u escape).
"""

from __future__ import annotations

import json
from pathlib import Path

from .app import WEB_DIR, Lab

CSP = ("default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; "
       "connect-src 'none'; base-uri 'none'; form-action 'none'")
TOKEN_META = '<meta name="lab-token" content="__LAB_TOKEN__">'
SCRIPT_START = "<script>\n(() => {"


def embed_json(obj) -> str:
    """JSON that is safe to put inside <script type="application/json"> (pure ASCII, no raw <, > or &)."""
    text = json.dumps(obj, separators=(",", ":"), ensure_ascii=True, sort_keys=False)
    return text.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


def render_page(snapshot: dict, page: str | None = None) -> str:
    """The static page: the app's HTML plus the embedded snapshot, a no-network policy and a description."""
    page = page if page is not None else (WEB_DIR / "index.html").read_text(encoding="utf-8")
    for needle in (TOKEN_META, SCRIPT_START, "</head>"):
        if page.count(needle) != 1:
            raise ValueError(f"The page template changed: expected exactly one {needle!r}")
    payload = snapshot["payload"]
    replay = payload.get("replay")
    parts = [f"{len(payload['rules'])} detection rules as code",
             f"tested on made-up logs with {len(payload['attacks'])} planted attacks"]
    if replay:
        parts.append(f"{replay['summary']['datasets']} public attack recordings")
    parts.append("a red-team set and an ATT&CK coverage map")
    description = "Detection engineering lab (read-only copy): " + ", ".join(parts) + ". A lab, not production experience."
    head = (f'<meta http-equiv="Content-Security-Policy" content="{CSP}">\n'
            f'<meta name="referrer" content="no-referrer">\n'
            f'<meta name="description" content="{description.replace(chr(34), "&quot;")}">\n')
    page = page.replace(TOKEN_META, '<meta name="lab-token" content="static">')
    page = page.replace("</head>", head + "</head>")
    return page.replace(SCRIPT_START, f'<script type="application/json" id="lab-snapshot">{embed_json(snapshot)}</script>\n'
                        + SCRIPT_START, 1)


def build_site(lab: Lab, out_dir: str | Path = "site") -> dict:
    """Write the static copy. Returns what was written and how big it is."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    html = render_page(lab.snapshot())
    (out / "index.html").write_text(html, encoding="utf-8")
    (out / ".nojekyll").write_text("", encoding="utf-8")          # GitHub Pages: serve the file as it is
    return {"files": ["index.html", ".nojekyll"], "bytes": len(html.encode("utf-8")), "directory": str(out)}
