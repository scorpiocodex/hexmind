"""Nmap port scanner runner: XML output parsed into structured port/service dict."""

from hexmind.recon.base_runner import BaseRunner, RunnerResult


class NmapRunner(BaseRunner):
    """Runs nmap with profile-appropriate flags and parses XML output."""

    name = "nmap"
    binary = "nmap"
    default_timeout = 600

    SAMPLE_OUTPUT: str = ""

    def build_command(self, target: str, flags: dict) -> list[str]:
        """Return the nmap argv for the given target and profile flags."""
        raise NotImplementedError("TODO: implement")

    def parse_output(self, raw: str, exit_code: int) -> dict:
        """Parse nmap XML output into a structured dict of hosts, ports, and services."""
        raise NotImplementedError("TODO: implement")
