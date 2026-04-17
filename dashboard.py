"""
CyberDash — Terminal-based Cyber Threat Intelligence Aggregator
================================================================
Stack  : Python 3, Textual, feedparser, requests
Author : @d0tahmed
Version: 3.0 — Dark Web Intel + Progress Bar + Expanded Feed Roster
"""

import re
import feedparser
from textual.app import App, ComposeResult
from textual.widgets import Header, Label, RichLog, Input, ProgressBar
from textual.binding import Binding
from textual import work
from datetime import datetime
from pathlib import Path

# ═══════════════════════════════════════════════════════════════════
#  FEED REGISTRY
#  Four categories — each gets its own source-tag color in the UI.
#
#  DARK WEB INTEL note: these are 100% legitimate open-source
#  journalism outlets (Krebs, The Record, DarkReading, CyberScoop)
#  that professionally track dark web markets, ransomware gangs,
#  and underground forum activity as part of public threat reporting.
# ═══════════════════════════════════════════════════════════════════

FEED_CATEGORIES: dict[str, dict] = {

    # ── Standard cyber news ────────────────────────────────────────
    "CLEARNET": {
        "tag_style": "bold red on #200000",
        "feeds": {
            "The Hacker News":   "https://feeds.feedburner.com/TheHackersNews",
            "Bleeping Computer": "https://www.bleepingcomputer.com/feed/",
            "SecurityWeek":      "https://feeds.feedburner.com/securityweek",
            "Ars Technica Sec":  "https://feeds.arstechnica.com/arstechnica/security",
            "Wired Security":    "https://www.wired.com/feed/category/security/latest/rss",
            "Exploit-DB":        "https://www.exploit-db.com/rss.xml",
        },
    },

    # ── Government advisories & vulnerability feeds ────────────────
    "GOV / ADVISORY": {
        "tag_style": "bold blue on #00001a",
        "feeds": {
            "CISA Advisories":   "https://www.cisa.gov/cybersecurity-advisories/all.xml",
            "US-CERT Alerts":    "https://www.cisa.gov/uscert/ncas/alerts.xml",
            "SANS ISC":          "https://isc.sans.edu/rssfeed_full.xml",
        },
    },

    # ── Legitimate journalism covering dark web markets & actors ───
    # These outlets publish open-source threat intelligence about
    # active underground markets, ransomware leak sites, and criminal
    # infrastructure — standard practice in professional CTI work.
    "DARK WEB INTEL": {
        "tag_style": "bold magenta on #1a001a",
        "feeds": {
            "KrebsOnSecurity":   "https://krebsonsecurity.com/feed/",
            "The Record":        "https://therecord.media/feed",
            "DarkReading":       "https://www.darkreading.com/rss_simple.asp",
            "CyberScoop":        "https://cyberscoop.com/feed/",
            "BankInfoSecurity":  "https://www.bankinfosecurity.com/rss-feeds",
        },
    },

    # ── Community feeds (Reddit, open forums) ─────────────────────
    "COMMUNITY": {
        "tag_style": "bold cyan on #001515",
        "feeds": {
            "r/netsec":          "https://www.reddit.com/r/netsec/new/.rss",
            "r/cybersecurity":   "https://www.reddit.com/r/cybersecurity/new/.rss",
            "r/0day":            "https://www.reddit.com/r/0day/new/.rss",
            "r/darkweb":         "https://www.reddit.com/r/darkweb/new/.rss",
        },
    },
}

# Flat list used by the progress bar: (category, source_name, url)
ALL_FEEDS: list[tuple[str, str, str]] = [
    (cat, name, url)
    for cat, meta in FEED_CATEGORIES.items()
    for name, url in meta["feeds"].items()
]

TOTAL_FEEDS = len(ALL_FEEDS)

# ═══════════════════════════════════════════════════════════════════
#  CVE INTELLIGENCE  (NVD REST API v2 — no key needed)
# ═══════════════════════════════════════════════════════════════════

CVE_REGEX = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
NVD_API   = "https://services.nvd.nist.gov/rest/json/cves/2.0"

SEVERITY_COLOR = {
    "CRITICAL": "bold red",
    "HIGH":     "bold orange1",
    "MEDIUM":   "bold yellow",
    "LOW":      "bold cyan",
    "NONE":     "dim white",
    "UNKNOWN":  "dim magenta",
}

def _score_to_severity(score: float) -> str:
    if score >= 9.0: return "CRITICAL"
    if score >= 7.0: return "HIGH"
    if score >= 4.0: return "MEDIUM"
    if score >  0.0: return "LOW"
    return "NONE"

def fetch_cvss(cve_id: str) -> tuple[str, float]:
    try:
        r = requests.get(
            NVD_API,
            params={"cveId": cve_id.upper()},
            timeout=4,
            headers={"User-Agent": "CyberDash-OSINT/3.0"},
        )
        r.raise_for_status()
        vulns = r.json().get("vulnerabilities", [])
        if not vulns:
            return "UNKNOWN", 0.0
        metrics = vulns[0]["cve"].get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics:
                score = metrics[key][0]["cvssData"]["baseScore"]
                return _score_to_severity(score), score
        return "UNKNOWN", 0.0
    except Exception:
        return "UNKNOWN", 0.0

# ═══════════════════════════════════════════════════════════════════
#  HIGH-ALERT KEYWORDS  →  ⚡ blink treatment
# ═══════════════════════════════════════════════════════════════════

HIGH_ALERT = re.compile(
    r"\b("
    r"zero.?day|0day|ransomware|rce|remote code execution|"
    r"active.?exploit|in the wild|poc released|critical|"
    r"data breach|nation.?state|apt|supply chain|backdoor|"
    r"privilege escalation|mass exploit|takedown|law enforcement|"
    r"marketplace|dark.?net market|seized|arrested|indicted"
    r")\b",
    re.IGNORECASE,
)

# ═══════════════════════════════════════════════════════════════════
#  DARK WEB KEYWORDS  →  🕸 badge overlay
#  Fires on any entry containing underground market terminology,
#  sourced from legitimate open-source threat journalism.
# ═══════════════════════════════════════════════════════════════════

DARKWEB_KEYWORDS = re.compile(
    r"\b("
    r"dark.?web|darknet|dark.?net|underground market|"
    r"ransomware.?gang|ransomware.?group|leak.?site|"
    r"lockbit|alphv|blackcat|cl0p|clop|hive|blackbasta|"
    r"tor network|onion site|initial access broker|"
    r"stolen data|data.?dump|credential.?dump|"
    r"cybercriminal|threat.?actor|hacking.?forum|"
    r"raidforums|breachforums|exploit\.in"
    r")\b",
    re.IGNORECASE,
)

# ═══════════════════════════════════════════════════════════════════
#  SPINNER FRAMES
# ═══════════════════════════════════════════════════════════════════

SPINNER = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

# ═══════════════════════════════════════════════════════════════════
#  HELP TEXT
# ═══════════════════════════════════════════════════════════════════

HELP_TEXT = """\
[bold green]━━━━━━━━━━━━━  CYBERDASH v3 COMMAND REFERENCE  ━━━━━━━━━━━━━[/bold green]
  [bold cyan]/filter [white]<keyword>[/white][/bold cyan]     — show only entries matching keyword
  [bold cyan]/filter off[/bold cyan]            — disable keyword filter
  [bold cyan]/category [white]<name>[/white][/bold cyan]    — show only a feed category
                           (CLEARNET · GOV / ADVISORY · DARK WEB INTEL · COMMUNITY)
  [bold cyan]/category off[/bold cyan]          — disable category filter
  [bold cyan]/stats[/bold cyan]                 — show per-category intel totals + ASCII bar chart
  [bold cyan]/clear[/bold cyan]                 — wipe the intel log
  [bold cyan]/export[/bold cyan]                — dump log to intel_export_<timestamp>.txt
  [bold cyan]/sources[/bold cyan]               — list all active feed sources by category
  [bold cyan]/help[/bold cyan]                  — this reference
[bold green]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/bold green]
"""

# ═══════════════════════════════════════════════════════════════════
#  APP
# ═══════════════════════════════════════════════════════════════════

class CyberDash(App):
    """Terminal-based Cyber Threat Intelligence aggregator — v3."""

    BINDINGS = [
        Binding("ctrl+c", "quit",       "Quit",   show=True),
        Binding("ctrl+l", "clear_log",  "Clear",  show=True),
        Binding("ctrl+e", "export_log", "Export", show=True),
        Binding("escape", "blur_input", "",       show=False),
    ]

    CSS = """
    Screen {
        background: #080c08;
        layers: base overlay;
    }

    Header {
        background: #0d1a0d;
        color: #00ff41;
        text-style: bold;
        border-bottom: solid #1a3a1a;
    }

    RichLog {
        background: #080c08;
        border: solid #1a3a1a;
        scrollbar-color: #00ff41 #0d1a0d;
        scrollbar-background: #0d1a0d;
        padding: 0 1;
    }

    /* Progress bar — hidden by default, shown during fetch */
    #fetch-bar {
        dock: bottom;
        height: 1;
        background: #080c08;
        display: none;
    }

    #fetch-bar.active {
        display: block;
    }

    ProgressBar > .bar--bar {
        color: #00ff41;
        background: #1a3a1a;
    }

    ProgressBar > .bar--complete {
        color: #00cc33;
        background: #1a3a1a;
    }

    #status-bar {
        dock: bottom;
        height: 1;
        background: #0d1a0d;
        color: #00cc33;
        text-style: bold;
        padding: 0 2;
        border-top: solid #1a3a1a;
    }

    #cmd-bar {
        dock: bottom;
        height: 3;
        background: #060a06;
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
    }
    """

    # ── State ──────────────────────────────────────────────────────
    def __init__(self) -> None:
        super().__init__()
        self.seen_urls:       set[str]         = set()
        self.cvss_cache:      dict[str, tuple] = {}
        self.filter_term:     str | None       = None
        self.category_filter: str | None       = None
        self.total_fetched:   int              = 0
        self._plain_log:      list[str]        = []
        self._spin_idx:       int              = 0
        self._fetching:       bool             = False
        self._cat_counts:     dict[str, int]   = {c: 0 for c in FEED_CATEGORIES}

    # ── Compose ────────────────────────────────────────────────────
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield RichLog(highlight=True, markup=True, id="intel-log")
        yield ProgressBar(total=TOTAL_FEEDS, show_eta=False, id="fetch-bar")
        yield Label("", id="status-bar")
        yield Input(placeholder="  ▶  /help for commands", id="cmd-bar")

    # ── Boot ───────────────────────────────────────────────────────
    def on_mount(self) -> None:
        self.query_one("#intel-log", RichLog).write(self._banner())
        self._set_status("SYSTEM BOOT — warming up feed connections…")
        self.fetch_news()
        self.set_interval(60.0, self.fetch_news)
        self.set_interval(0.1,  self._tick_spinner)

    # ── Spinner ticker ─────────────────────────────────────────────
    def _tick_spinner(self) -> None:
        if not self._fetching:
            return
        self._spin_idx = (self._spin_idx + 1) % len(SPINNER)
        frame      = SPINNER[self._spin_idx]
        feeds_done = int(self.query_one("#fetch-bar", ProgressBar).progress)
        filt = f"  [yellow]FILTER:'{self.filter_term}'[/yellow]" if self.filter_term else ""
        cat  = f"  [magenta]CAT:{self.category_filter}[/magenta]" if self.category_filter else ""
        self._set_status(
            f"[bold green]{frame} SWEEPING {feeds_done}/{TOTAL_FEEDS} FEEDS…[/bold green]  "
            f"│  Total: {self.total_fetched}{filt}{cat}"
        )

    # ── Command bar ────────────────────────────────────────────────
    def on_input_submitted(self, event: Input.Submitted) -> None:
        cmd = event.value.strip()
        event.input.value = ""
        log = self.query_one("#intel-log", RichLog)
        if not cmd:
            return

        c = cmd.lower()

        if c == "/help":
            log.write(HELP_TEXT)

        elif c.startswith("/filter "):
            term = cmd[8:].strip()
            if term.lower() == "off":
                self.filter_term = None
                log.write("[bold green][ FILTER OFF — all intel visible ][/bold green]\n")
            else:
                self.filter_term = term.lower()
                log.write(f"[bold yellow][ FILTER ACTIVE: '{term}' ][/bold yellow]\n")

        elif c.startswith("/category "):
            cat = cmd[10:].strip()
            if cat.lower() == "off":
                self.category_filter = None
                log.write("[bold green][ CATEGORY FILTER OFF ][/bold green]\n")
            else:
                match = next(
                    (k for k in FEED_CATEGORIES if cat.upper() in k.upper()), None
                )
                if match:
                    self.category_filter = match
                    log.write(f"[bold magenta][ CATEGORY FILTER: {match} ][/bold magenta]\n")
                else:
                    cats = " · ".join(FEED_CATEGORIES.keys())
                    log.write(f"[bold red][ UNKNOWN CATEGORY — valid: {cats} ][/bold red]\n")

        elif c == "/stats":
            log.write(self._build_stats())

        elif c == "/clear":
            self.action_clear_log()

        elif c == "/export":
            self.action_export_log()

        elif c == "/sources":
            self._cmd_sources(log)

        else:
            log.write(f"[bold red][ UNKNOWN: '{cmd}' — /help ][/bold red]\n")

    # ── Actions ────────────────────────────────────────────────────
    def action_clear_log(self) -> None:
        log = self.query_one("#intel-log", RichLog)
        log.clear()
        self._plain_log.clear()
        log.write(self._banner())

    def action_blur_input(self) -> None:
        self.query_one("#cmd-bar", Input).blur()

    def action_export_log(self) -> None:
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = Path(f"intel_export_{ts}.txt")
        path.write_text("\n".join(self._plain_log), encoding="utf-8")
        self.query_one("#intel-log", RichLog).write(
            f"[bold green][ EXPORT → {path.resolve()} ][/bold green]\n"
        )

    # ── Background feed fetcher ────────────────────────────────────
    @work(thread=True)
    def fetch_news(self) -> None:
        self._fetching = True
        new_this_sweep = 0

        self.call_from_thread(self._progress_start)

        for category, source_name, url in ALL_FEEDS:

            # Category filter gate
            if self.category_filter and self.category_filter != category:
                self.call_from_thread(self._progress_advance)
                continue

            try:
                feed = feedparser.parse(url)
            except Exception:
                self.call_from_thread(self._progress_advance)
                continue

            # Pull up to 15 entries per feed for maximum daily coverage
            for entry in feed.entries[:15]:
                link  = getattr(entry, "link",  None)
                title = getattr(entry, "title", "Unknown Threat")

                if not link or link in self.seen_urls:
                    continue

                # Keyword filter gate
                if self.filter_term and self.filter_term not in title.lower():
                    continue

                self.seen_urls.add(link)
                self.total_fetched      += 1
                self._cat_counts[category] += 1
                new_this_sweep          += 1

                # CVE enrichment
                cve_badge   = ""
                cve_matches = CVE_REGEX.findall(title)
                if cve_matches:
                    cve_id = cve_matches[0].upper()
                    if cve_id not in self.cvss_cache:
                        self.cvss_cache[cve_id] = fetch_cvss(cve_id)
                    severity, score = self.cvss_cache[cve_id]
                    color     = SEVERITY_COLOR[severity]
                    score_str = f"{score:.1f}" if score > 0 else "N/A"
                    cve_badge = f" [{color}][ {cve_id} ▸ {severity} {score_str} ][/{color}]"

                is_alert   = bool(HIGH_ALERT.search(title))
                is_darkweb = bool(DARKWEB_KEYWORDS.search(title))

                ts      = datetime.now().strftime("%H:%M:%S")
                payload = self._format_entry(
                    ts, category, source_name, title, link,
                    cve_badge, is_alert, is_darkweb,
                )
                self.call_from_thread(self.push_to_log, payload, title)

            self.call_from_thread(self._progress_advance)

        self._fetching = False
        self.call_from_thread(self._progress_done, new_this_sweep)

    # ── Progress bar helpers ───────────────────────────────────────
    def _progress_start(self) -> None:
        bar = self.query_one("#fetch-bar", ProgressBar)
        bar.update(progress=0, total=TOTAL_FEEDS)
        bar.add_class("active")

    def _progress_advance(self) -> None:
        self.query_one("#fetch-bar", ProgressBar).advance(1)

    def _progress_done(self, new_count: int) -> None:
        self.query_one("#fetch-bar", ProgressBar).remove_class("active")
        ts     = datetime.now().strftime("%H:%M:%S")
        status = (
            f"[bold green]▲ +{new_count} NEW[/bold green]"
            if new_count else "[dim]● NO NEW DROPS[/dim]"
        )
        filt = f"  [yellow]FILTER:'{self.filter_term}'[/yellow]" if self.filter_term else ""
        cat  = f"  [magenta]CAT:{self.category_filter}[/magenta]" if self.category_filter else ""
        self._set_status(
            f"[{ts}]  {status}  │  Feeds: {TOTAL_FEEDS}  │  "
            f"Cache: {len(self.seen_urls)}  │  Total: {self.total_fetched}{filt}{cat}"
        )

    # ── Render helpers ─────────────────────────────────────────────
    def _format_entry(
        self,
        ts:         str,
        category:   str,
        source:     str,
        title:      str,
        link:       str,
        cve_badge:  str,
        is_alert:   bool,
        is_darkweb: bool,
    ) -> str:
        style    = FEED_CATEGORIES[category]["tag_style"]
        time_tag = f"[bold green][{ts}][/bold green]"
        cat_tag  = f"[{style}]  {category}  [/{style}]"
        src_tag  = f"[dim white]{source}[/dim white]"
        dw_badge = " [bold magenta][ 🕸 DARK WEB ][/bold magenta]" if is_darkweb else ""
        sep      = "[dim #152015]" + "─" * 74 + "[/dim #152015]"

        if is_alert:
            title_tag = f"[blink][bold red]⚡ {title}[/bold red][/blink]"
        else:
            title_tag = f"[bold white]{title}[/bold white]"

        link_tag = f"[dim #3a6a3a]{link}[/dim #3a6a3a]"

        return (
            f"{time_tag} {cat_tag} {src_tag}{cve_badge}{dw_badge}\n"
            f"  [bold green]▶[/bold green] {title_tag}\n"
            f"    {link_tag}\n"
            f"{sep}\n"
        )

    def push_to_log(self, payload: str, plain_title: str) -> None:
        self.query_one("#intel-log", RichLog).write(payload)
        self._plain_log.append(plain_title)

    def _set_status(self, msg: str) -> None:
        self.query_one("#status-bar", Label).update(msg)

    # ── /stats ─────────────────────────────────────────────────────
    def _build_stats(self) -> str:
        lines = "[bold green]━━━  INTEL TOTALS BY CATEGORY  ━━━[/bold green]\n"
        max_count = max(self._cat_counts.values(), default=1) or 1
        for cat, count in self._cat_counts.items():
            style   = FEED_CATEGORIES[cat]["tag_style"]
            bar_len = int((count / max_count) * 36)
            bar     = "█" * bar_len
            lines  += (
                f"  [{style}] {cat:20s} [/{style}]  "
                f"[green]{bar:<36s}[/green] [bold white]{count}[/bold white]\n"
            )
        lines += (
            f"\n  [dim]Cache:[/dim]        [bold green]{len(self.seen_urls)}[/bold green] unique URLs\n"
            f"  [dim]Grand total:[/dim]  [bold green]{self.total_fetched}[/bold green] items fetched\n"
            f"  [dim]Active feeds:[/dim] [bold green]{TOTAL_FEEDS}[/bold green] sources · "
            f"[bold green]{len(FEED_CATEGORIES)}[/bold green] categories\n"
        )
        return lines

    # ── /sources ───────────────────────────────────────────────────
    def _cmd_sources(self, log: RichLog) -> None:
        lines = ""
        for cat, meta in FEED_CATEGORIES.items():
            style = meta["tag_style"]
            lines += f"\n[{style}]  {cat}  [/{style}]\n"
            for name, url in meta["feeds"].items():
                lines += (
                    f"    [bold white]{name}[/bold white]\n"
                    f"    [dim #3a6a3a]{url}[/dim #3a6a3a]\n"
                )
        log.write(lines)

    # ── Banner ─────────────────────────────────────────────────────
    @staticmethod
    def _banner() -> str:
        return (
            "[bold green]\n"
            "   ██████╗██╗   ██╗██████╗ ███████╗██████╗ ██████╗  █████╗ ███████╗██╗  ██╗\n"
            "  ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔══██╗██╔════╝██║  ██║\n"
            "  ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██║  ██║███████║███████╗███████║\n"
            "  ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██║  ██║██╔══██║╚════██║██╔══██║\n"
            "  ╚██████╗   ██║   ██████╔╝███████╗██║  ██║██████╔╝██║  ██║███████║██║  ██║\n"
            "   ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝\n"
            "[/bold green]"
            "[dim #1a3a1a]" + "─" * 78 + "[/dim #1a3a1a]\n"
            "[bold white]"
            "  ██████╗  ██████╗ ████████╗ █████╗ ██╗  ██╗███╗   ███╗███████╗██████╗ \n"
            "  ██╔══██╗██╔═████╗╚══██╔══╝██╔══██╗██║  ██║████╗ ████║██╔════╝██╔══██╗\n"
            "  ██║  ██║██║██╔██║   ██║   ███████║███████║██╔████╔██║█████╗  ██║  ██║\n"
            "  ██║  ██║████╔╝██║   ██║   ██╔══██║██╔══██║██║╚██╔╝██║██╔══╝  ██║  ██║\n"
            "  ██████╔╝╚██████╔╝   ██║   ██║  ██║██║  ██║██║ ╚═╝ ██║███████╗██████╔╝\n"
            "  ╚═════╝  ╚═════╝    ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝╚═════╝ \n"
            "[/bold white]"
            f"[dim green]    OPEN-SOURCE CYBER THREAT INTELLIGENCE  ·  v3.0  ·  "
            f"{TOTAL_FEEDS} feeds · {len(FEED_CATEGORIES)} categories[/dim green]\n"
            "[dim #1a3a1a]" + "━" * 78 + "[/dim #1a3a1a]\n"
            "  [bold red on #200000] CLEARNET [/bold red on #200000]  "
            "[bold blue on #00001a] GOV/ADVISORY [/bold blue on #00001a]  "
            "[bold magenta on #1a001a] DARK WEB INTEL [/bold magenta on #1a001a]  "
            "[bold cyan on #001515] COMMUNITY [/bold cyan on #001515]\n"
            "  [dim]CVE enrichment · ⚡ high-alert tags · 🕸 dark web markers · /help for commands[/dim]\n"
            "[dim #1a3a1a]" + "━" * 78 + "[/dim #1a3a1a]\n"
        )


# ═══════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    CyberDash().run()