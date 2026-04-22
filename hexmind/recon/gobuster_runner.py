"""Gobuster directory brute-forcer runner: parses discovered paths and status codes."""

from hexmind.recon.base_runner import BaseRunner, RunnerResult
from hexmind.constants import WORDLIST_PATH


class GobusterRunner(BaseRunner):
    """Runs gobuster dir mode against HTTP targets and parses found paths."""

    name = "gobuster"
    binary = "gobuster"
    default_timeout = 600

    SAMPLE_OUTPUT: str = ""

    def build_command(self, target: str, flags: dict) -> list[str]:
        """Return the gobuster argv using the bundled wordlist."""
        raise NotImplementedError("TODO: implement")

    def parse_output(self, raw: str, exit_code: int) -> dict:
        """Parse gobuster line output into a list of path/status-code dicts."""
        raise NotImplementedError("TODO: implement")
