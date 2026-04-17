# CyberDash

CyberDash is a lightweight, terminal-based Threat Intelligence Dashboard. It asynchronously aggregates live cybersecurity news, zero-day vulnerabilities, and threat advisories from multiple authoritative sources directly into a standard Linux terminal interface.

## Features

* Asynchronous Fetching: Retrieves data in background threads to ensure the Terminal User Interface (TUI) remains responsive.
* Multi-Source Aggregation: Parses live RSS feeds from The Hacker News, Bleeping Computer, CISA Cyber Advisories, and Krebs on Security.
* Broad Compatibility: Runs flawlessly on native terminal emulators across major Linux distributions including Fedora, Kali Linux, Ubuntu, Parrot OS, and Arch Linux.
* Live Data Monitor: Tracks the volume of pulled intelligence and active sources in real-time via a docked status bar.
* Low Resource Overhead: Built to minimize CPU and RAM footprint compared to heavy browser-based web dashboards.

## Prerequisites

* Python 3.x
* `venv` (Python Virtual Environment module)

## Installation

1. Clone the repository and navigate into the directory:
   ```bash
   git clone https://github.com/d0tahmed/CYBER-DASH.git
   cd CYBER-DASH

    Create and activate a virtual environment:
    Bash

    python3 -m venv venv
    source venv/bin/activate

    Install the required dependencies:
    Bash

    pip install textual feedparser

Usage

Ensure your virtual environment is active, then execute the main script:
Bash

python3S dashboard.py

Scroll through the feeds using your mouse wheel or arrow keys. To exit the dashboard, press Ctrl+C.
Configuration

To add or modify threat intelligence sources, edit the TARGET_FEEDS dictionary located at the top of the dashboard.py file. Define the source name as the key and the raw RSS/XML feed URL as the value.
Python

TARGET_FEEDS = {
    "Target Source Name": "[https://url-to-rss-feed.xml](https://url-to-rss-feed.xml)",
    "The Hacker News": "[https://feeds.feedburner.com/TheHackersNews](https://feeds.feedburner.com/TheHackersNews)",
    # ...
}

Built With

    Textual - The TUI framework for Python.

    Feedparser - For parsing RSS and Atom feeds.
