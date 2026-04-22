"""Nikto web vulnerability scanner runner: JSON output parsed into finding list."""

from hexmind.recon.base_runner import BaseRunner, RunnerResult


class NiktoRunner(BaseRunner):
    """Runs nikto against HTTP/HTTPS targets and parses JSON vulnerability output."""

    name = "nikto"
    binary = "nikto"
    default_timeout = 900

    SAMPLE_OUTPUT: str = ""

    def build_command(self, target: str, flags: dict) -> list[str]:
        """Return the nikto argv, writing JSON output to a temp file."""
        raise NotImplementedError("TODO: implement")

    def parse_output(self, raw: str, exit_code: int) -> dict:
        """Parse nikto JSON output into a list of vulnerability dicts."""
        raise NotImplementedError("TODO: implement")
