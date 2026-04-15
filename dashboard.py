import feedparser
from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, Static, Label
from textual.containers import VerticalScroll
from textual import work

# Our dictionary of authentic, top-tier cybersecurity intelligence feeds
TARGET_FEEDS = {
    "The Hacker News": "https://feeds.feedburner.com/TheHackersNews",
    "Bleeping Computer": "https://www.bleepingcomputer.com/feed/",
    "CISA Cyber Advisories": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    "Krebs on Security": "https://krebsonsecurity.com/feed/"
}

class NewsFeed(Static):
    """A widget to display updating news from external sources."""
    
    def on_mount(self) -> None:
        self.update("[bold green]Initializing Global Threat Sweep...[/bold green]")
        self.fetch_news()
        # Refresh every 5 minutes (300 seconds)
        self.set_interval(300.0, self.fetch_news)

    @work(thread=True)
    def fetch_news(self) -> None:
        """Background thread to fetch from multiple APIs without freezing the UI."""
        content = ""
        total_fetched = 0
        
        # Loop through every source in our target list
        for source_name, url in TARGET_FEEDS.items():
            feed = feedparser.parse(url)
            
            # Create a clean header for each source
            content += f"[bold red]=== {source_name.upper()} ===[/bold red]\n"
            content += "[dim]--------------------------------------------------------[/dim]\n"
            
            # Grab the top 5 latest reports from each source
            for entry in feed.entries[:5]: 
                content += f"[bold yellow]>[/bold yellow] [bold white]{entry.title}[/bold white]\n"
                content += f"  [dim blue]{entry.link}[/dim blue]\n\n"
                total_fetched += 1
                
        # Send the compiled data and the total count back to the main UI
        self.app.call_from_thread(self.update_ui, content, total_fetched)
        
    def update_ui(self, content: str, count: int) -> None:
        """Safely updates the screen with the fetched data."""
        self.update(content)
        # Update the data monitor label
        stats_monitor = self.app.query_one("#data-monitor", Label)
        stats_monitor.update(f"Live Monitor Active | Sources Scanned: {len(TARGET_FEEDS)} | Total Intel Fetched: {count} reports")

class CyberDash(App):
    """A Textual dashboard for Cyber Threat Intelligence."""
    
    # Custom CSS for the layout and the new Data Monitor
    CSS = """
    #data-monitor {
        dock: bottom;
        width: 100%;
        background: green;
        color: black;
        text-style: bold;
        padding: 0 2;
    }
    NewsFeed {
        padding: 1 2;
    }
    """

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        # This VerticalScroll container lets you use your mouse/keyboard to scroll
        with VerticalScroll():
            yield NewsFeed()
        # The new Data Monitor bar
        yield Label("System Booting | Fetching initial data payloads...", id="data-monitor")

if __name__ == "__main__":
    app = CyberDash()
    app.run()