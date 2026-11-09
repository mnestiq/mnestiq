"""Where the dashboard page is, for the checks that run it."""

from pathlib import Path

import mnestiq.dashboard


def html() -> Path:
    return Path(mnestiq.dashboard.__file__).with_name("index.html")
