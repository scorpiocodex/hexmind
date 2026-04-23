"""Gobuster directory brute-forcer runner: parses discovered paths and status codes."""

from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path

from hexmind.recon.base_runner import BaseRunner, RunnerResult
from hexmind.constants import WORDLIST_PATH

_INTERESTING_PATTERNS: list[str] = [
    "admin", "backup", ".git", ".env", "config",
    "wp-admin", "phpmyadmin", "manager", "console",
    "dashboard", "api", ".htaccess", "web.config",
    "phpinfo", "debug", "test",
]

_LINE_RE = re.compile(
    r"^(/[^\s]*)\s+\(Status:\s*(\d+)\)(?:\s+\[Size:\s*(\d+)\])?",
    re.IGNORECASE,
)


class GobusterRunner(BaseRunner):
    """Runs gobuster dir mode against HTTP targets and parses found paths."""

    name            = "gobuster"
    binary          = "gobuster"
    default_timeout = 300

    def build_command(self, target: str, flags: dict) -> list[str]:
        """Build gobuster dir command.

        flags keys:
          wordlist (str): path override — defaults to bundled wordlist
          threads (int): thread count — default 20
          port (str): target port — affects scheme selection
        """
        self._tmp_out: str = tempfile.mktemp(
            prefix="hexmind_gobuster_", suffix=".txt"
        )
        wordlist = flags.get("wordlist", str(WORDLIST_PATH))
        threads  = str(flags.get("threads", 20))
        port     = str(flags.get("port", ""))

        scheme = "https" if port in ("443", "8443") else "http"
        if port and port not in ("80", "443"):
            url = f"{scheme}://{target}:{port}"
        else:
            url = f"{scheme}://{target}"

        return [
            "gobuster", "dir",
            "-u", url,
            "-w", wordlist,
            "-o", self._tmp_out,
            "-q",
            "--no-error",
            "-t", threads,
        ]

    def parse_output(self, raw: str, exit_code: int) -> dict:
        """Parse gobuster output file.

        Line format: /path (Status: 200) [Size: 1234]

        Returns:
          results: list[{path, status_code, size}]
          found_200: list[str]
          redirects: list[str]
          forbidden_403: list[str]
          interesting: list[str]  — paths matching sensitive name patterns
          total_found: int
        """
        out_path = getattr(self, "_tmp_out", None)
        content  = ""

        if out_path and Path(out_path).exists():
            try:
                content = Path(out_path).read_text(encoding="utf-8")
            except Exception:
                pass
            finally:
                try:
                    os.unlink(out_path)
                except Exception:
                    pass

        if not content:
            content = raw

        results:     list[dict] = []
        found_200:   list[str]  = []
        redirects:   list[str]  = []
        forbidden:   list[str]  = []
        interesting: list[str]  = []

        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = _LINE_RE.match(line)
            if not m:
                continue
            path        = m.group(1)
            status_code = int(m.group(2))
            size        = int(m.group(3)) if m.group(3) else 0

            results.append({"path": path, "status_code": status_code, "size": size})

            if status_code == 200:
                found_200.append(path)
            elif status_code in (301, 302, 307, 308):
                redirects.append(path)
            elif status_code == 403:
                forbidden.append(path)

            path_lower = path.lower()
            if any(p in path_lower for p in _INTERESTING_PATTERNS):
                interesting.append(path)

        return {
            "results":       results,
            "found_200":     found_200,
            "redirects":     redirects,
            "forbidden_403": forbidden,
            "interesting":   interesting,
            "total_found":   len(results),
        }
