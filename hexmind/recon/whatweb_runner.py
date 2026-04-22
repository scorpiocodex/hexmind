"""WhatWeb technology fingerprinter runner: JSON output parsed into tech stack dict."""

from hexmind.recon.base_runner import BaseRunner, RunnerResult


class WhatWebRunner(BaseRunner):
    """Runs whatweb and parses detected technologies, versions, and plugins."""

    name = "whatweb"
    binary = "whatweb"
    default_timeout = 60

    SAMPLE_OUTPUT: str = ""

    def build_command(self, target: str, flags: dict) -> list[str]:
        """Return the whatweb argv writing JSON log to a temp file."""
        raise NotImplementedError("TODO: implement")

    def parse_output(self, raw: str, exit_code: int) -> dict:
        """Parse whatweb JSON output into a list of detected technology dicts."""
        raise NotImplementedError("TODO: implement")
