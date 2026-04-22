"""Curl HTTP header runner: extracts server info and security header presence."""

from hexmind.recon.base_runner import BaseRunner, RunnerResult


class CurlRunner(BaseRunner):
    """Runs curl -sI to capture response headers and flags missing security headers."""

    name = "curl"
    binary = "curl"
    default_timeout = 30

    SAMPLE_OUTPUT: str = ""

    def build_command(self, target: str, flags: dict) -> list[str]:
        """Return the curl argv for header-only fetch with follow-redirect."""
        raise NotImplementedError("TODO: implement")

    def parse_output(self, raw: str, exit_code: int) -> dict:
        """Parse curl header output into a dict of header names and their values."""
        raise NotImplementedError("TODO: implement")
