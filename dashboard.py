"""
CyberDash — Terminal-based Cyber Threat Intelligence Aggregator
================================================================
Stack  : Python 3, Textual, feedparser, requests
Author : @d0tahmed
Version: 2.0 — CVE Intelligence Layer + Command Bar
"""

import re
import feedparser
from textual.app import App, ComposeResult
from textual.widgets import Header, Label, RichLog, Input
from textual.binding import Binding
from textual import work
from datetime import datetime
from pathlib import Path

# ─────────────────────────────────────────────
#  FEED SOURCES
# ─────────────────────────────────────────────
TARGET_FEEDS = {
    "The Hacker News":     "https://feeds.feedburner.com/TheHackersNews",
    "Bleeping Computer":   "https://www.bleepingcomputer.com/feed/",
    "CISA Advisories":     "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    "Netsec (Reddit)":     "https://www.reddit.com/r/netsec/new/.rss",
    "CyberSecurity (Reddit)": "https://www.reddit.com/r/cybersecurity/new/.rss",
    "0day (Reddit)":       "https://www.reddit.com/r/0day/new/.rss",
}

# ─────────────────────────────────────────────
#  CVE INTELLIGENCE
# ─────────────────────────────────────────────
CVE_REGEX = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
NVD_API   = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# CVSS v3 score → severity string
def _score_to_severity(score: float) -> str:
    if score >= 9.0: return "CRITICAL"
    if score >= 7.0: return "HIGH"
    if score >= 4.0: return "MEDIUM"
    if score >  0.0: return "LOW"
    return "NONE"

# Severity → Rich markup color
SEVERITY_COLOR = {
    "CRITICAL": "bold red",
    "HIGH":     "bold orange1",
    "MEDIUM":   "bold yellow",
    "LOW":      "bold cyan",
    "NONE":     "dim white",
    "UNKNOWN":  "dim magenta",
}

def fetch_cvss(cve_id: str) -> tuple[str, float]:
    """
    Hit the NVD REST API v2 for a CVE ID.
    Returns (severity_string, base_score). No API key needed.
    Times out in 4 s to keep the feed loop snappy.
    """
    try:
        resp = requests.get(
            NVD_API,
            params={"cveId": cve_id.upper()},
            timeout=4,
            headers={"User-Agent": "CyberDash-OSINT/2.0"},
        )
        resp.raise_for_status()
        data = resp.json()
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return "UNKNOWN", 0.0

        metrics = vulns[0]["cve"].get("metrics", {})

        # Prefer CVSSv3.1 → v3.0 → v2 fallback
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics:
                entry = metrics[key][0]
                if "cvssMetricV2" in key:
                    score = entry["cvssData"]["baseScore"]
                else:
                    score = entry["cvssData"]["baseScore"]
                return _score_to_severity(score), score

        return "UNKNOWN", 0.0
    except Exception:
        return "UNKNOWN", 0.0


# ─────────────────────────────────────────────
#  HIGH-ALERT KEYWORD PATTERNS
#  Any title matching these gets a ⚡ ALERT box
# ─────────────────────────────────────────────
HIGH_ALERT_KEYWORDS = re.compile(
    r"\b("
    r"zero.?day|0day|ransomware|rce|remote code execution|"
    r"active.?exploit|in the wild|poc released|critical|"
    r"data breach|nation.?state|apt|supply chain|backdoor|"
    r"privilege escalation|mass exploit"
    r")\b",
    re.IGNORECASE,
)


# ─────────────────────────────────────────────
#  COMMAND HELP TEXT
# ─────────────────────────────────────────────
HELP_TEXT = """\
[bold green]━━━━━━━━━━━━━━━━━  CYBERDASH COMMAND REFERENCE  ━━━━━━━━━━━━━━━━━[/bold green]
  [bold cyan]/filter [bold white]<keyword>[/bold white][/bold cyan]   — only display entries containing keyword
  [bold cyan]/filter off[/bold cyan]          — disable active filter
  [bold cyan]/clear[/bold cyan]               — wipe the intel log
  [bold cyan]/export[/bold cyan]              — dump log to [white]intel_export_<timestamp>.txt[/white]
  [bold cyan]/sources[/bold cyan]             — list all active feed sources
  [bold cyan]/help[/bold cyan]                — show this reference
[bold green]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/bold green]\
"""


# ─────────────────────────────────────────────
#  APP
# ─────────────────────────────────────────────
class CyberDash(App):
    """Terminal-based Cyber Threat Intelligence aggregator."""

    BINDINGS = [
        Binding("ctrl+c", "quit",           "Quit",           show=True),
        Binding("ctrl+l", "clear_log",      "Clear Log",      show=True),
        Binding("ctrl+e", "export_log",     "Export",         show=True),
        Binding("escape", "blur_input",     "Defocus Input",  show=False),
    ]

    CSS = """
    /* ── Layout ─────────────────────────────── */
    Screen {
        background: #0a0e0a;
        layers: base overlay;
    }

    Header {
        background: #0d1a0d;
        color: #00ff41;
        text-style: bold;
        border-bottom: solid #1a3a1a;
    }

    RichLog {
        background: #0a0e0a;
        border: solid #1a3a1a;
        scrollbar-color: #00ff41 #0d1a0d;
        scrollbar-background: #0d1a0d;
        padding: 0 1;
    }

    /* ── Status bar ──────────────────────────── */
    #status-bar {
        dock: bottom;
        height: 1;
        background: #0d1a0d;
        color: #00cc33;
        text-style: bold;
        padding: 0 2;
        border-top: solid #1a3a1a;
    }

    /* ── Command input ───────────────────────── */
    #cmd-bar {
        dock: bottom;
        height: 3;
        background: #080c08;
        border: solid #1a4a1a;
        border-top: solid #00ff41;
        padding: 0 1;
        color: #00ff41;
    }

    #cmd-bar:focus-within {
        border: solid #00ff41;
        background: #0d1a0d;
    }

    Input {
        background: transparent;
        border: none;
        color: #00ff41;
        padding: 0 1;
    }

    Input:focus {
        border: none;
        outline: none;
    }
    """

    # ── State ──────────────────────────────────
    def __init__(self) -> None:
        super().__init__()
        self.seen_urls:   set[str]         = set()
        self.cvss_cache:  dict[str, tuple] = {}   # cve_id → (severity, score)
        self.filter_term: str | None       = None
        self.total_fetched: int            = 0
        self._plain_log:  list[str]        = []   # for export (strip markup later)

    # ── Compose ────────────────────────────────
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield RichLog(highlight=True, markup=True, id="intel-log")
        yield Label("", id="status-bar")
        yield Input(
            placeholder="  > type a command  (/help for reference)",
            id="cmd-bar",
        )

    # ── Boot ───────────────────────────────────
    def on_mount(self) -> None:
        log = self.query_one("#intel-log", RichLog)
        log.write(self._banner())
        self._set_status("SYSTEM BOOT — establishing feed connections…")
        self.fetch_news()
        self.set_interval(60.0, self.fetch_news)

    # ── Command bar handler ────────────────────
    def on_input_submitted(self, event: Input.Submitted) -> None:
        cmd = event.value.strip()
        event.input.value = ""  # clear the bar

        log = self.query_one("#intel-log", RichLog)

        if not cmd:
            return

        if cmd.lower() == "/help":
            log.write(HELP_TEXT)

        elif cmd.lower().startswith("/filter "):
            term = cmd[8:].strip()
            if term.lower() == "off":
                self.filter_term = None
                log.write("[bold green][ FILTER DISABLED — showing all intel ][/bold green]\n")
                self._set_status("Filter: OFF")
            else:
                self.filter_term = term.lower()
                log.write(f"[bold yellow][ FILTER ACTIVE: '{term}' — only matching entries shown ][/bold yellow]\n")
                self._set_status(f"Filter: '{term}'")

        elif cmd.lower() == "/clear":
            self.action_clear_log()

        elif cmd.lower() == "/export":
            self.action_export_log()

        elif cmd.lower() == "/sources":
            lines = "[bold green]━━━  ACTIVE FEED SOURCES  ━━━[/bold green]\n"
            for name, url in TARGET_FEEDS.items():
                lines += f"  [bold cyan]{name}[/bold cyan]\n  [dim]{url}[/dim]\n"
            log.write(lines)

        else:
            log.write(f"[bold red][ UNKNOWN COMMAND: '{cmd}' — try /help ][/bold red]\n")

    # ── Keybinding actions ─────────────────────
    def action_clear_log(self) -> None:
        self.query_one("#intel-log", RichLog).clear()
        self._plain_log.clear()
        self.query_one("#intel-log", RichLog).write(self._banner())

    def action_blur_input(self) -> None:
        self.query_one("#cmd-bar", Input).blur()

    def action_export_log(self) -> None:
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = Path(f"intel_export_{ts}.txt")
        path.write_text("\n".join(self._plain_log), encoding="utf-8")
        log = self.query_one("#intel-log", RichLog)
        log.write(f"[bold green][ EXPORT OK → {path.resolve()} ][/bold green]\n")

    # ── Background feed fetcher ────────────────
    @work(thread=True)
    def fetch_news(self) -> None:
        new_intel_found = False

        for source_name, url in TARGET_FEEDS.items():
            try:
                feed = feedparser.parse(url)
            except Exception:
                continue

            for entry in feed.entries[:10]:
                link  = getattr(entry, "link",  None)
                title = getattr(entry, "title", "Unknown Threat")

                if not link or link in self.seen_urls:
                    continue

                # ── Filter gate ───────────────
                if self.filter_term and self.filter_term not in title.lower():
                    continue

                self.seen_urls.add(link)
                self.total_fetched += 1
                new_intel_found = True

                # ── CVE detection ─────────────
                cve_matches = CVE_REGEX.findall(title)
                cve_badge   = ""
                if cve_matches:
                    cve_id = cve_matches[0].upper()
                    if cve_id not in self.cvss_cache:
                        self.cvss_cache[cve_id] = fetch_cvss(cve_id)
                    severity, score = self.cvss_cache[cve_id]
                    color = SEVERITY_COLOR[severity]
                    score_str = f"{score:.1f}" if score > 0 else "N/A"
                    cve_badge = (
                        f" [{color}][ {cve_id}  ▸  {severity}  {score_str} ][/{color}]"
                    )

                # ── High-alert keyword check ──
                is_alert = bool(HIGH_ALERT_KEYWORDS.search(title))

                # ── Build payload ─────────────
                ts = datetime.now().strftime("%H:%M:%S")
                payload = self._format_entry(
                    ts, source_name, title, link, cve_badge, is_alert
                )

                self.call_from_thread(self.push_to_log, payload, title)

        self.call_from_thread(self.update_status_bar, new_intel_found)

    # ── Render helpers ─────────────────────────
    def _format_entry(
        self,
        ts:          str,
        source:      str,
        title:       str,
        link:        str,
        cve_badge:   str,
        is_alert:    bool,
    ) -> str:
        time_tag   = f"[bold green][{ts}][/bold green]"
        source_tag = f"[bold red on #1a0000]  {source.upper()}  [/bold red on #1a0000]"

        if is_alert:
            title_tag = f"[blink][bold red]⚡ {title}[/bold red][/blink]"
        else:
            title_tag = f"[bold white]{title}[/bold white]"

        link_tag  = f"[dim #4a8a4a]{link}[/dim #4a8a4a]"
        separator = "[dim #1a3a1a]" + "─" * 72 + "[/dim #1a3a1a]"

        return (
            f"{time_tag} {source_tag}{cve_badge}\n"
            f"  [bold green]▶[/bold green] {title_tag}\n"
            f"    {link_tag}\n"
            f"{separator}\n"
        )

    def push_to_log(self, payload: str, plain_title: str) -> None:
        self.query_one("#intel-log", RichLog).write(payload)
        self._plain_log.append(plain_title)

    def update_status_bar(self, new_intel: bool) -> None:
        ts     = datetime.now().strftime("%H:%M:%S")
        status = "[bold green]NEW INTEL[/bold green]" if new_intel else "[dim]NO NEW DROPS[/dim]"
        filt   = f"  [yellow]FILTER: '{self.filter_term}'[/yellow]" if self.filter_term else ""
        self._set_status(
            f"[{ts}]  {status}  │  Cache: {len(self.seen_urls)}  │  "
            f"Total: {self.total_fetched}{filt}"
        )

    def _set_status(self, msg: str) -> None:
        self.query_one("#status-bar", Label).update(msg)

    # ── Splash banner ──────────────────────────
    @staticmethod
    def _banner() -> str:
        return (
            # ── Main title (green) ────────────────────────────────────────────
            "[bold green]\n"
            "   ██████╗██╗   ██╗██████╗ ███████╗██████╗ ██████╗  █████╗ ███████╗██╗  ██╗\n"
            "  ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔══██╗██╔════╝██║  ██║\n"
            "  ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██║  ██║███████║███████╗███████║\n"
            "  ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██║  ██║██╔══██║╚════██║██╔══██║\n"
            "  ╚██████╗   ██║   ██████╔╝███████╗██║  ██║██████╔╝██║  ██║███████║██║  ██║\n"
            "   ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝\n"
            "[/bold green]"
            # ── Divider ───────────────────────────────────────────────────────
            "[dim #1a3a1a]" + "─" * 78 + "[/dim #1a3a1a]\n"
            # ── Author handle (white-on-black, ansi_shadow) ───────────────────
            "[bold white]"
            "  ██████╗  ██████╗ ████████╗ █████╗ ██╗  ██╗███╗   ███╗███████╗██████╗ \n"
            "  ██╔══██╗██╔═████╗╚══██╔══╝██╔══██╗██║  ██║████╗ ████║██╔════╝██╔══██╗\n"
            "  ██║  ██║██║██╔██║   ██║   ███████║███████║██╔████╔██║█████╗  ██║  ██║\n"
            "  ██║  ██║████╔╝██║   ██║   ██╔══██║██╔══██║██║╚██╔╝██║██╔══╝  ██║  ██║\n"
            "  ██████╔╝╚██████╔╝   ██║   ██║  ██║██║  ██║██║ ╚═╝ ██║███████╗██████╔╝\n"
            "  ╚═════╝  ╚═════╝    ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝╚═════╝ \n"
            "[/bold white]"
            # ── Subtitle & meta ───────────────────────────────────────────────
            "[dim green]              OPEN-SOURCE CYBER THREAT INTELLIGENCE  ·  v2.0[/dim green]\n"
            "[dim #1a3a1a]" + "━" * 78 + "[/dim #1a3a1a]\n"
            "  [dim]Feeds: THN · BleepingComputer · CISA · r/netsec · r/cybersecurity · r/0day[/dim]\n"
            "  [dim]CVE enrichment via NVD API  ·  Type [/dim][bold cyan]/help[/bold cyan][dim] for commands[/dim]\n"
            "[dim #1a3a1a]" + "━" * 78 + "[/dim #1a3a1a]\n"
        )


if __name__ == "__main__":
    CyberDash().run()