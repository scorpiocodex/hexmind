"""WhatWeb technology fingerprinter runner: JSON output parsed into tech stack dict."""

from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path

from hexmind.recon.base_runner import BaseRunner, RunnerResult


class WhatWebRunner(BaseRunner):
    """Runs whatweb and parses detected technologies, versions, and plugins."""

    name            = "whatweb"
    binary          = "whatweb"
    default_timeout = 60

    SAMPLE_OUTPUT: str = (
        '[{"target":"http://example.com",'
        '"http_status":200,'
        '"plugins":{"Apache":{"version":["2.4.49"],"string":["Apache"]},'
        '"PHP":{"version":["7.2.5"]},'
        '"WordPress":{"version":["5.8.1"]}}}]'
    )

    _CMS_NAMES: frozenset[str] = frozenset({
        "WordPress", "Joomla", "Drupal", "Shopify",
        "Magento", "Ghost", "Wix", "Squarespace",
    })
    _LANG_NAMES: frozenset[str] = frozenset({
        "PHP", "Python", "Ruby", "ASP.NET",
        "Java", "Node.js", "Go",
    })
    _SERVER_NAMES: frozenset[str] = frozenset({
        "Apache", "Nginx", "IIS", "LiteSpeed",
        "Caddy", "Tomcat",
    })
    _FRAME_NAMES: frozenset[str] = frozenset({
        "Laravel", "Django", "Rails", "Express",
        "Spring", "Flask", "Symfony", "CodeIgniter",
    })

    def build_command(self, target: str, flags: dict) -> list[str]:
        """Write JSON output to a temp file via --log-json."""
        url = target
        if not url.startswith(("http://", "https://")):
            url = f"http://{target}"

        self._tmp_path: str = tempfile.mktemp(
            prefix="hexmind_whatweb_", suffix=".json"
        )
        return [
            "whatweb",
            f"--log-json={self._tmp_path}",
            "--color=never",
            "--quiet",
            url,
        ]

    def parse_output(self, raw: str, exit_code: int) -> dict:
        """Read the JSON log file written by whatweb; fall back to raw stdout.

        Returns:
          target_url (str), http_status (int),
          technologies (list[{name, version, string}]),
          cms (str|None), language (str|None),
          server (str|None), framework (str|None),
          interesting (list[str]), plugin_count (int)
        """
        raw_json = ""

        tmp = getattr(self, "_tmp_path", None)
        if tmp and Path(tmp).exists():
            try:
                raw_json = Path(tmp).read_text(encoding="utf-8")
            except Exception:
                pass
            finally:
                try:
                    os.unlink(tmp)
                except Exception:
                    pass

        if not raw_json:
            raw_json = raw

        data: list[dict] = []
        try:
            parsed = json.loads(raw_json)
            data = parsed if isinstance(parsed, list) else [parsed]
        except (json.JSONDecodeError, ValueError):
            m = re.search(r"\[.*\]", raw_json, re.DOTALL)
            if m:
                try:
                    data = json.loads(m.group(0))
                except Exception:
                    pass

        if not data:
            return {
                "target_url":   "",
                "http_status":  0,
                "technologies": [],
                "cms":          None,
                "language":     None,
                "server":       None,
                "framework":    None,
                "interesting":  [],
                "plugin_count": 0,
                "error":        "no JSON output",
            }

        entry   = data[0]
        plugins = entry.get("plugins", {})

        technologies: list[dict] = []
        for name, info in plugins.items():
            tech: dict = {"name": name, "version": None, "string": None}
            if isinstance(info, dict):
                versions = info.get("version", [])
                strings  = info.get("string",  [])
                tech["version"] = versions[0] if versions else None
                tech["string"]  = strings[0]  if strings  else None
            technologies.append(tech)

        plugin_names = set(plugins.keys())
        cms       = next((n for n in plugin_names if n in self._CMS_NAMES),    None)
        language  = next((n for n in plugin_names if n in self._LANG_NAMES),   None)
        server    = next((n for n in plugin_names if n in self._SERVER_NAMES), None)
        framework = next((n for n in plugin_names if n in self._FRAME_NAMES),  None)

        interesting: list[str] = []
        for tech in technologies:
            n, v = tech["name"], tech["version"]
            if n in self._CMS_NAMES    and v:
                interesting.append(f"CMS: {n} {v}")
            if n in self._SERVER_NAMES and v:
                interesting.append(f"Server: {n} {v}")
            if n in self._LANG_NAMES   and v:
                interesting.append(f"Language: {n} {v}")

        return {
            "target_url":   entry.get("target", ""),
            "http_status":  entry.get("http_status", 0),
            "technologies": technologies,
            "cms":          cms,
            "language":     language,
            "server":       server,
            "framework":    framework,
            "interesting":  interesting,
            "plugin_count": len(technologies),
        }
