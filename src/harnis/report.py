"""Terminal line and the one-page report for a blocked action."""

from __future__ import annotations

import html
import json
import os
import sys
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from harnis.policy import Decision


@dataclass(frozen=True)
class Incident:
    phrase: str
    policy: str
    line: str
    recorded_at: str


class Session:
    def __init__(self, path: Path, log_path: Path | None = None):
        self.path = Path(path)
        self.log_path = Path(log_path) if log_path else self.path.with_name(self.path.name + ".events.jsonl")
        self.incidents: list[Incident] = []
        self._lock = threading.Lock()

    @property
    def blocked(self) -> bool:
        return bool(self._load())

    def already_recorded(self, decision: Decision) -> bool:
        key = (decision.phrase, decision.policy or "")
        for incident in self._load():
            if (incident.phrase, incident.policy) == key:
                return True
        return False

    def record(self, decision: Decision) -> None:
        incident = Incident(
            phrase=decision.phrase,
            policy=decision.policy or "",
            line=decision.line(),
            recorded_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        )
        with self._lock:
            self.incidents.append(incident)
            self._append(incident)

    def write(self) -> None:
        incidents = self._load()
        text = render_html(incidents)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        temporary.write_text(text, encoding="utf-8")
        temporary.replace(self.path)

    def _append(self, incident: Incident) -> None:
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(
            {
                "phrase": incident.phrase,
                "policy": incident.policy,
                "line": incident.line,
                "recorded_at": incident.recorded_at,
            },
            ensure_ascii=False,
        ).encode("utf-8") + b"\n"
        fd = os.open(self.log_path, os.O_APPEND | os.O_CREAT | os.O_WRONLY)
        try:
            os.write(fd, payload)
        finally:
            os.close(fd)

    def _load(self) -> tuple[Incident, ...]:
        if not self.log_path.exists():
            with self._lock:
                return tuple(self.incidents)
        incidents: list[Incident] = []
        for line in self.log_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            data = json.loads(line)
            incidents.append(
                Incident(
                    phrase=data["phrase"],
                    policy=data["policy"],
                    line=data["line"],
                    recorded_at=data["recorded_at"],
                )
            )
        return tuple(incidents)


def emit(decision: Decision) -> None:
    _emit_line(decision.line())


def emit_finding(finding) -> None:
    _emit_line(getattr(finding, "line", str(finding)))


def _emit_line(line: str) -> None:
    if sys.stderr.isatty():
        for token in ("BLOCKED", "FINDING"):
            if token in line:
                line = line.replace(token, f"\033[1;31m{token}\033[0m", 1)
                break
    data = (line + "\n").encode("utf-8", "replace")
    buffer = getattr(sys.stderr, "buffer", None)
    if buffer is None:
        sys.stderr.write(line + "\n")
        sys.stderr.flush()
        return
    buffer.write(data)
    buffer.flush()


def render_html(incidents: tuple[Incident, ...] | list[Incident]) -> str:
    if not incidents:
        body = _clear_sheet()
        title = "Harnis — nothing blocked"
    else:
        body = _blocked_sheet(tuple(incidents))
        title = f"Harnis — {len(incidents)} blocked"
    return _page(title, body)


def render_findings(findings: list) -> str:
    if not findings:
        body = """<article class="sheet">
  <div class="brand">Harnis</div>
  <div class="kicker">Probe</div>
  <h1>Clear</h1>
  <div class="rule"></div>
  <p class="phrase">No violating tool chain was offered.</p>
  <footer>Scripted prompts ran. The agent did not propose a blocked tool call.</footer>
</article>"""
        return _page("Harnis — probe clear", body)
    lead = findings[0]
    extras = ""
    if len(findings) > 1:
        extras = '<section class="more">\n' + "\n".join(
            _finding_extra(item) for item in findings[1:]
        ) + "\n</section>"
    replay = _replay_html(lead.replay)
    body = f"""<article class="sheet">
  <div class="brand">Harnis</div>
  <div class="kicker">Probe finding</div>
  <h1>Finding</h1>
  <div class="rule"></div>
  <p class="phrase">{html.escape(lead.line)}</p>
  <div class="policy">policy: {html.escape(lead.policy)}</div>
  <dl>
    <dt>Scenario</dt><dd>{html.escape(lead.scenario)}</dd>
    <dt>Action</dt><dd>{html.escape(lead.phrase)}</dd>
  </dl>
  <section class="more">
    <article>
      <h2>Replay</h2>
      {replay}
    </article>
  </section>
  {extras}
  <footer>Reproducible against this agent. Harnis did not execute the tool call.</footer>
</article>"""
    return _page(f"Harnis — {len(findings)} finding(s)", body)


def _finding_extra(finding) -> str:
    return (
        "<article>"
        f"<h2>{html.escape(finding.line)}</h2>"
        f"<div class=\"policy\">policy: {html.escape(finding.policy)}</div>"
        "</article>"
    )


def _replay_html(replay) -> str:
    parts = []
    for turn in replay:
        role = html.escape(getattr(turn, "role", ""))
        text = html.escape(getattr(turn, "text", "") or "")
        parts.append(f"<p><strong>{role}</strong>: {text}</p>")
        for call in getattr(turn, "tool_calls", ()) or ():
            name = html.escape(str(call.get("name", "")))
            arguments = html.escape(str(call.get("arguments", {})))
            parts.append(f"<p class=\"policy\">tool {name} {arguments}</p>")
    return "\n".join(parts)


def _page(title: str, body: str) -> str:
    safe_title = html.escape(title)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{safe_title}</title>
<style>
  :root {{
    --ink: #1c1612;
    --muted: #6d6256;
    --sheet: #f4efe6;
    --red: #9d1c1c;
    --line: rgba(28, 22, 18, 0.14);
    --serif: "Iowan Old Style", "Palatino Linotype", Palatino, Georgia, serif;
    --mono: "Cascadia Mono", "IBM Plex Mono", Consolas, ui-monospace, monospace;
    --sans: "Segoe UI", "Helvetica Neue", Helvetica, sans-serif;
  }}
  * {{ box-sizing: border-box; }}
  html, body {{ margin: 0; min-height: 100%; }}
  body {{
    color: var(--ink);
    font-family: var(--sans);
    background: #16120e;
  }}
  .ambient {{
    position: fixed;
    inset: -12%;
    pointer-events: none;
    background:
      radial-gradient(ellipse at 20% 0%, rgba(180, 92, 48, 0.18), transparent 46%),
      radial-gradient(ellipse at 90% 80%, rgba(157, 28, 28, 0.12), transparent 42%),
      #16120e;
    z-index: 0;
  }}
  main {{
    position: relative;
    z-index: 1;
    max-width: 720px;
    margin: 0 auto;
    padding: 48px 20px 72px;
  }}
  .sheet {{
    background: var(--sheet);
    padding: 40px 40px 32px;
    box-shadow: 0 24px 60px rgba(0, 0, 0, 0.28);
  }}
  .brand {{
    font-family: var(--mono);
    font-size: 12px;
    letter-spacing: 0.22em;
    text-transform: uppercase;
    color: var(--muted);
  }}
  .kicker {{
    margin-top: 28px;
    font-family: var(--mono);
    font-size: 12px;
    letter-spacing: 0.18em;
    text-transform: uppercase;
    color: var(--red);
  }}
  h1 {{
    margin: 8px 0 0;
    font-family: var(--serif);
    font-weight: 500;
    font-size: 64px;
    line-height: 0.95;
    letter-spacing: -0.03em;
    color: var(--red);
  }}
  .rule {{
    height: 2px;
    width: 100%;
    margin: 22px 0 22px;
    background: var(--red);
    transform-origin: left center;
  }}
  .phrase {{
    font-family: var(--serif);
    font-size: 28px;
    line-height: 1.35;
    margin: 0;
    text-wrap: pretty;
  }}
  .policy {{
    display: inline-block;
    margin-top: 18px;
    padding: 4px 8px;
    font-family: var(--mono);
    font-size: 13px;
    letter-spacing: 0.02em;
    border: 1px solid var(--line);
  }}
  dl {{
    margin: 28px 0 0;
    display: grid;
    grid-template-columns: 7.5rem 1fr;
    gap: 8px 12px;
    font-family: var(--mono);
    font-size: 13px;
  }}
  dt {{ color: var(--muted); }}
  dd {{ margin: 0; overflow-wrap: anywhere; }}
  .more {{ margin-top: 28px; border-top: 1px solid var(--line); padding-top: 8px; }}
  .more article {{ padding: 14px 0; border-bottom: 1px solid var(--line); }}
  .more h2 {{
    margin: 0;
    font-family: var(--serif);
    font-size: 18px;
    font-weight: 500;
  }}
  footer {{
    margin-top: 28px;
    color: var(--muted);
    font-size: 13px;
  }}
  @media (prefers-reduced-motion: no-preference) {{
    .ambient {{ animation: drift 28s ease-in-out infinite; }}
    .kicker, h1 {{ animation: rise 0.9s cubic-bezier(.22,1,.36,1) both; }}
    .rule {{ animation: draw 1.1s cubic-bezier(.22,1,.36,1) 0.12s both; }}
  }}
  @keyframes rise {{
    from {{ opacity: 0; transform: translateY(12px); }}
    to {{ opacity: 1; transform: none; }}
  }}
  @keyframes draw {{
    from {{ transform: scaleX(0); }}
    to {{ transform: scaleX(1); }}
  }}
  @keyframes drift {{
    0% {{ transform: translate3d(0, 0, 0); }}
    50% {{ transform: translate3d(1.5%, -1%, 0); }}
    100% {{ transform: translate3d(0, 0, 0); }}
  }}
  @media (prefers-reduced-motion: reduce) {{
    .ambient, .kicker, h1, .rule, .phrase, .policy {{ animation: none; }}
  }}
  @media (max-width: 640px) {{
    .sheet {{ padding: 28px 20px 24px; }}
    h1 {{ font-size: 46px; }}
    .phrase {{ font-size: 22px; }}
    dl {{ grid-template-columns: 1fr; }}
  }}
</style>
</head>
<body>
<div class="ambient" aria-hidden="true"></div>
<main>
{body}
</main>
</body>
</html>
"""


def _blocked_sheet(incidents: tuple[Incident, ...]) -> str:
    lead = incidents[0]
    extras = ""
    if len(incidents) > 1:
        items = "\n".join(_extra(incident) for incident in incidents[1:])
        extras = f'<section class="more">\n{items}\n</section>'
    return f"""<article class="sheet">
  <div class="brand">Harnis</div>
  <div class="kicker">Runtime denial</div>
  <h1>Blocked</h1>
  <div class="rule"></div>
  <p class="phrase">{html.escape(lead.line)}</p>
  <div class="policy">policy: {html.escape(lead.policy)}</div>
  <dl>
    <dt>When</dt><dd>{html.escape(lead.recorded_at)}</dd>
    <dt>Action</dt><dd>{html.escape(lead.phrase)}</dd>
  </dl>
  {extras}
  <footer>Denied before the action completed. The agent did not receive the result.</footer>
</article>"""


def _extra(incident: Incident) -> str:
    return (
        "<article>"
        f"<h2>{html.escape(incident.phrase)}</h2>"
        f"<div class=\"policy\">policy: {html.escape(incident.policy)}</div>"
        "</article>"
    )


def _clear_sheet() -> str:
    return """<article class="sheet">
  <div class="brand">Harnis</div>
  <div class="kicker">Runtime</div>
  <h1>Clear</h1>
  <div class="rule"></div>
  <p class="phrase">Nothing was blocked.</p>
  <footer>The agent finished without tripping a default policy.</footer>
</article>"""
