"""Whois runner: extracts registrar, dates, nameservers, and ASN information."""

from hexmind.recon.base_runner import BaseRunner, RunnerResult


class WhoisRunner(BaseRunner):
    """Runs whois and extracts registration metadata via regex."""

    name = "whois"
    binary = "whois"
    default_timeout = 30

    SAMPLE_OUTPUT: str = ""

    def build_command(self, target: str, flags: dict) -> list[str]:
        """Return the whois argv for the given target."""
        raise NotImplementedError("TODO: implement")

    def parse_output(self, raw: str, exit_code: int) -> dict:
        """Parse whois text output into a structured dict of registration fields."""
        raise NotImplementedError("TODO: implement")
