"""Nikto web vulnerability scanner runner: JSON output parsed into finding list."""

from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path

from hexmind.recon.base_runner import BaseRunner, RunnerResult


class NiktoRunner(BaseRunner):
    """Runs nikto against HTTP/HTTPS targets and parses JSON vulnerability output."""

    name            = "nikto"
    binary          = "nikto"
    default_timeout = 900

    TUNING_MODES: dict[str, list[str]] = {
        "light": ["-Tuning", "1,2,3,9"],
        "full":  [],
    }

    def build_command(self, target: str, flags: dict) -> list[str]:
        """Build nikto command with JSON output to temp file.

        flags keys:
          nikto_mode (str): "light" | "full" — default "light"
          port (str|int): optional target port
        """
        self._tmp_json: str = tempfile.mktemp(
            prefix="hexmind_nikto_", suffix=".json"
        )
        mode   = flags.get("nikto_mode", "light")
        port   = flags.get("port", "")
        tuning = self.TUNING_MODES.get(mode, [])

        cmd = [
            "nikto",
            "-h", target,
            "-Format", "json",
            "-output", self._tmp_json,
            "-nointeractive",
            "-ask", "no",
        ]
        if port:
            cmd += ["-p", str(port)]
        cmd += tuning
        return cmd

    def parse_output(self, raw: str, exit_code: int) -> dict:
        """Read nikto's JSON output file; falls back to raw stdout.

        Returns:
          target_ip (str), target_port (str), target_hostname (str),
          server_banner (str|None),
          vulnerabilities: list[{id, osvdb_id, method, url,
                                  description, references}],
          total_findings (int)
        """
        json_path = getattr(self, "_tmp_json", None)
        raw_json  = ""

        if json_path and Path(json_path).exists():
            try:
                raw_json = Path(json_path).read_text(encoding="utf-8")
            except Exception:
                pass
            finally:
                try:
                    os.unlink(json_path)
                except Exception:
                    pass

        if not raw_json:
            raw_json = raw

        data: dict | list = {}
        try:
            data = json.loads(raw_json)
        except (json.JSONDecodeError, ValueError):
            # Nikto sometimes produces trailing-comma JSON — attempt repair
            cleaned = re.sub(r",\s*}", "}", re.sub(r",\s*]", "]", raw_json))
            try:
                data = json.loads(cleaned)
            except Exception:
                pass

        # nikto JSON schema varies: list, {"vulnerabilities": [...]},
        # or {"host": [{"vulnerabilities": [...]}]}
        vulns_raw: list = []
        if isinstance(data, list):
            vulns_raw = data
        elif isinstance(data, dict):
            host_list = data.get("host", [])
            if isinstance(host_list, list) and host_list:
                vulns_raw = host_list[0].get("vulnerabilities", [])
            else:
                vulns_raw = data.get("vulnerabilities", [])

        vulnerabilities: list[dict] = []
        for v in vulns_raw:
            if not isinstance(v, dict):
                continue
            vulnerabilities.append({
                "id":          v.get("id",          v.get("nikto_id",    "")),
                "osvdb_id":    v.get("OSVDB",        v.get("osvdb",       "")),
                "method":      v.get("method",       "GET"),
                "url":         v.get("url",          v.get("uri",         "")),
                "description": v.get("msg",          v.get("description", "")),
                "references":  v.get("references",   []),
            })

        # Host-level metadata
        host_info: dict = {}
        if isinstance(data, dict):
            host_list = data.get("host", [])
            if isinstance(host_list, list) and host_list:
                host_info = host_list[0]
            else:
                host_info = data

        return {
            "target_ip":       host_info.get("ip",       ""),
            "target_port":     host_info.get("port",     ""),
            "target_hostname": host_info.get("hostname", ""),
            "server_banner":   host_info.get("banner",   None),
            "vulnerabilities": vulnerabilities,
            "total_findings":  len(vulnerabilities),
        }
