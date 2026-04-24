"""Nmap port scanner runner: XML output parsed into structured port/service dict."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from hexmind.recon.base_runner import BaseRunner, RunnerResult


class NmapRunner(BaseRunner):
    """Runs nmap with profile-appropriate flags and parses XML output."""

    name            = "nmap"
    binary          = "nmap"
    default_timeout = 600

    PROFILE_FLAGS: dict[str, list[str]] = {
        "quick":    ["-T4", "-F", "--open"],
        "standard": ["-T3", "-sV", "-sC", "--open"],
        "deep":     ["-T3", "-sV", "-sC", "--open",
                     "-p-", "--script", "vuln,default"],
        "stealth":  ["-T1", "-sT", "-sV", "--open"],
    }

    def build_command(self, target: str, flags: dict) -> list[str]:
        """Build nmap command with profile flags and XML output to temp file.

        flags keys:
          profile (str): scan profile name — default "standard"
          custom_args (list[str]): override profile flags for agentic runs
        """
        self._tmp_xml: str = tempfile.mktemp(
            prefix="hexmind_nmap_", suffix=".xml"
        )
        profile     = flags.get("profile", "standard")
        custom_args = flags.get("custom_args", [])

        if custom_args:
            profile_flags = list(custom_args)
        else:
            profile_flags = list(self.PROFILE_FLAGS.get(
                profile, self.PROFILE_FLAGS["standard"]
            ))

        return ["nmap"] + profile_flags + ["-oX", self._tmp_xml, target]

    def parse_output(self, raw: str, exit_code: int) -> dict:
        """Parse nmap XML output file; falls back to empty result on failure.

        Returns:
          hosts: list of {address, hostnames, status, mac}
          ports: list of {port_id, protocol, state, service_name,
                          service_version, service_product, service_extra,
                          scripts: list[{id, output}]}
          os_matches: list of {name, accuracy} (top 3)
          open_ports: list[int]
          has_web: bool  — port 80/443/8080/8443/8000/3000/5000 open
          has_db:  bool  — common DB ports open
          vulnerable_scripts: list[str]  — script IDs containing VULNERABLE
          scan_stats: {elapsed, summary}
        """
        import xmltodict

        xml_path = getattr(self, "_tmp_xml", None)
        xml_raw  = ""

        if xml_path and Path(xml_path).exists():
            try:
                xml_raw = Path(xml_path).read_text(encoding="utf-8")
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

        nm_run    = data.get("nmaprun", {})
        hosts_raw = nm_run.get("host", [])
        if isinstance(hosts_raw, dict):
            hosts_raw = [hosts_raw]

        hosts:        list[dict] = []
        all_ports:    list[dict] = []
        os_matches:   list[dict] = []
        vuln_scripts: list[str]  = []

        for host in hosts_raw:
            # Addresses
            addrs = host.get("address", [])
            if isinstance(addrs, dict):
                addrs = [addrs]
            ip_addr  = next(
                (a["@addr"] for a in addrs
                 if a.get("@addrtype") in {"ipv4", "ipv6"}), ""
            )
            mac_addr = next(
                (a["@addr"] for a in addrs
                 if a.get("@addrtype") == "mac"), None
            )

            # Hostnames
            hn_wrap = host.get("hostnames") or {}
            hn_list = hn_wrap.get("hostname", [])
            if isinstance(hn_list, dict):
                hn_list = [hn_list]
            hostnames = [h.get("@name", "") for h in hn_list]

            status = host.get("status", {}).get("@state", "unknown")
            hosts.append({
                "address":   ip_addr,
                "hostnames": hostnames,
                "status":    status,
                "mac":       mac_addr,
            })

            # Ports
            ports_wrap = host.get("ports") or {}
            ports_raw  = ports_wrap.get("port", [])
            if isinstance(ports_raw, dict):
                ports_raw = [ports_raw]

            for p in ports_raw:
                state = p.get("state", {}).get("@state", "")
                if state != "open":
                    continue
                svc         = p.get("service") or {}
                scripts_raw = p.get("script", [])
                if isinstance(scripts_raw, dict):
                    scripts_raw = [scripts_raw]
                scripts = [
                    {"id": s.get("@id", ""), "output": s.get("@output", "")}
                    for s in scripts_raw
                ]
                for s in scripts:
                    if "VULNERABLE" in s.get("output", "").upper():
                        vuln_scripts.append(s["id"])

                all_ports.append({
                    "port_id":         int(p.get("@portid", 0)),
                    "protocol":        p.get("@protocol", "tcp"),
                    "state":           state,
                    "service_name":    svc.get("@name",      ""),
                    "service_version": svc.get("@version",   ""),
                    "service_product": svc.get("@product",   ""),
                    "service_extra":   svc.get("@extrainfo", ""),
                    "scripts":         scripts,
                })

            # OS detection
            os_wrap = host.get("os") or {}
            os_list = os_wrap.get("osmatch", [])
            if isinstance(os_list, dict):
                os_list = [os_list]
            for om in os_list[:3]:
                os_matches.append({
                    "name":     om.get("@name",     ""),
                    "accuracy": int(om.get("@accuracy", 0)),
                })

        open_port_nums = [p["port_id"] for p in all_ports]
        web_ports      = {80, 443, 8080, 8443, 8000, 3000, 5000}
        db_ports       = {3306, 5432, 1433, 27017, 6379, 9200}

        runstats = nm_run.get("runstats") or {}
        finished = runstats.get("finished") or {}

        result = {
            "hosts":              hosts,
            "ports":              all_ports,
            "os_matches":         os_matches,
            "open_ports":         open_port_nums,
            "has_web":            bool(set(open_port_nums) & web_ports),
            "has_db":             bool(set(open_port_nums) & db_ports),
            "vulnerable_scripts": list(set(vuln_scripts)),
            "scan_stats": {
                "elapsed": finished.get("@elapsed", ""),
                "summary": finished.get("@summary", ""),
            },
        }

        if not result["ports"] and raw and len(raw) > 50:
            result = self._parse_raw_fallback(raw, result)

        return result

    def _parse_raw_fallback(self, raw: str, base: dict) -> dict:
        """Fallback parser for nmap text output when XML produces no ports."""
        import re
        port_re = re.compile(r"(\d+)/(tcp|udp)\s+open\s+(\S+)(?:\s+(.+))?")
        ports:     list[dict] = []
        open_nums: list[int]  = []

        for line in raw.splitlines():
            m = port_re.match(line.strip())
            if m:
                port_id  = int(m.group(1))
                protocol = m.group(2)
                svc_name = m.group(3)
                svc_info = (m.group(4) or "").strip()

                product = ""
                version = ""
                info_parts = svc_info.split()
                if info_parts:
                    product = info_parts[0]
                    if len(info_parts) > 1:
                        version = info_parts[1].strip("()")

                ports.append({
                    "port_id":         port_id,
                    "protocol":        protocol,
                    "state":           "open",
                    "service_name":    svc_name,
                    "service_version": version,
                    "service_product": product,
                    "service_extra":   svc_info,
                    "scripts":         [],
                })
                open_nums.append(port_id)

        if ports:
            web_ports = {80, 443, 8080, 8443, 8000, 3000, 5000}
            db_ports  = {3306, 5432, 1433, 27017, 6379, 9200}
            base["ports"]      = ports
            base["open_ports"] = open_nums
            base["has_web"]    = bool(set(open_nums) & web_ports)
            base["has_db"]     = bool(set(open_nums) & db_ports)

        return base

    def _empty_result(self) -> dict:
        return {
            "hosts": [], "ports": [], "os_matches": [],
            "open_ports": [], "has_web": False, "has_db": False,
            "vulnerable_scripts": [], "scan_stats": {},
        }

    async def agentic_run(
        self, target: str, custom_args: list[str]
    ) -> RunnerResult:
        """Run nmap with AI-requested custom arguments."""
        return await self.run(target, flags={"custom_args": custom_args})
