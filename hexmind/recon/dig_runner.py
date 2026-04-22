"""Dig DNS runner: queries A, MX, TXT, and reverse records for a target."""

from hexmind.recon.base_runner import BaseRunner, RunnerResult


class DigRunner(BaseRunner):
    """Runs multiple dig queries and aggregates DNS record results."""

    name = "dig"
    binary = "dig"
    default_timeout = 30

    SAMPLE_OUTPUT: str = ""

    def build_command(self, target: str, flags: dict) -> list[str]:
        """Return the primary dig argv; additional record types run separately."""
        raise NotImplementedError("TODO: implement")

    def parse_output(self, raw: str, exit_code: int) -> dict:
        """Parse dig text output into a structured dict of DNS records."""
        raise NotImplementedError("TODO: implement")
