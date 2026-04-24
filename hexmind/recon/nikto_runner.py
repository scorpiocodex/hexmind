"""Nikto web vulnerability scanner runner: XML output parsed into finding list."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from hexmind.recon.base_runner import BaseRunner, RunnerResult


class NiktoRunner(BaseRunner):
    """Runs nikto against HTTP/HTTPS targets and parses XML vulnerability output."""

    name            = "nikto"
    binary          = "nikto"
    default_timeout = 900

    TUNING_MODES: dict[str, list[str]] = {
        "light": ["-Tuning", "1,2,3,9"],
        "full":  [],
    }

    def build_command(self, target: str, flags: dict) -> list[str]:
        """Output to temp XML file — JSON not supported on all nikto installs."""
        self._tmp_xml: str = tempfile.mktemp(
            prefix="hexmind_nikto_", suffix=".xml"
        )
        mode   = flags.get("nikto_mode", "light")
        port   = flags.get("port", "80")
        tuning = self.TUNING_MODES.get(mode, [])

        cmd = [
            "nikto",
            "-h", target,
            "-p", str(port),
            "-Format", "xml",
            "-output", self._tmp_xml,
            "-nointeractive",
            "-maxtime", "120",
        ]
        cmd += tuning
        return cmd

    def parse_output(self, raw: str, exit_code: int) -> dict:
        """
        Parse nikto XML output.
        Nikto XML format:
          <niktoscan>
            <scandetails ...>
              <item id="..." method="..." uri="...">
                <description>...</description>
                <osvdbid>...</osvdbid>
                <osvdblink>...</osvdblink>
                <namelink>...</namelink>
              </item>
              ...
            </scandetails>
          </niktoscan>
        """
        import xmltodict

        xml_path = getattr(self, "_tmp_xml", None)
        xml_raw  = ""

        if xml_path and Path(xml_path).exists():
            try:
                xml_raw = Path(xml_path).read_text(
                    encoding="utf-8", errors="replace"
                )
            except Exception:
                pass
            finally:
                try:
                    os.unlink(xml_path)
                except Exception:
                    pass

        if not xml_raw:
            return self._empty_result()

        try:
            data = xmltodict.parse(xml_raw)
        except Exception:
            return self._empty_result()

        scan        = data.get("niktoscan", {})
        details_raw = scan.get("scandetails", {})

        # scandetails can be dict (single host) or list (multiple)
        if isinstance(details_raw, list):
            details = details_raw[0] if details_raw else {}
        else:
            details = details_raw

        target_ip   = details.get("@targetip",          "")
        target_port = details.get("@targetport",         "")
        target_host = details.get("@targethostname",     "")
        banner      = details.get("@sitename",           "")

        items_raw = details.get("item", [])
        if isinstance(items_raw, dict):
            items_raw = [items_raw]

        vulnerabilities: list[dict] = []
        for item in items_raw:
            if not isinstance(item, dict):
                continue
            desc   = item.get("description", "")
            uri    = item.get("@uri",    item.get("uri",    ""))
            method = item.get("@method", item.get("method", "GET"))
            osvdb  = item.get("osvdbid", item.get("@osvdbid", ""))

            if desc:
                vulnerabilities.append({
                    "id":          item.get("@id", ""),
                    "osvdb_id":    osvdb,
                    "method":      method,
                    "url":         uri,
                    "description": desc,
                    "references":  [
                        item.get("osvdblink", ""),
                        item.get("namelink",  ""),
                    ],
                })

        return {
            "target_ip":       target_ip,
            "target_port":     target_port,
            "target_hostname": target_host,
            "server_banner":   banner,
            "vulnerabilities": vulnerabilities,
            "total_findings":  len(vulnerabilities),
        }

    def _empty_result(self) -> dict:
        return {
            "target_ip":       "",
            "target_port":     "",
            "target_hostname": "",
            "server_banner":   None,
            "vulnerabilities": [],
            "total_findings":  0,
        }
