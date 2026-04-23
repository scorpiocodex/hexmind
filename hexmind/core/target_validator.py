"""Target validation: checks IP/domain format and scope restrictions."""

from __future__ import annotations

import ipaddress
import re

from hexmind.core.exceptions import ValidationError

_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]

_DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,}$"
)


class TargetValidator:
    """Validates scan targets against format rules and scope restrictions."""

    def validate(
        self, target: str, allow_private: bool = False
    ) -> tuple[bool, str, str]:
        """Validate and classify a target string.

        Returns:
            (is_valid, normalized_target, target_type)
            target_type: "ip" | "domain" | "cidr"

        Raises ValidationError with descriptive message on failure.
        """
        target = target.strip()
        if not target:
            raise ValidationError("Target cannot be empty.")

        # Step 1: Try IPv4 or IPv6 address
        try:
            addr = ipaddress.ip_address(target)
            normalized = str(addr)
            if self._is_private(addr) and not allow_private:
                raise ValidationError(
                    f"'{normalized}' is a private/loopback address. "
                    "Use --allow-private to scan RFC1918 or localhost targets."
                )
            return True, normalized, "ip"
        except ValueError:
            pass

        # Step 2: Try CIDR notation (only if "/" present to avoid re-parsing plain IPs)
        if "/" in target:
            try:
                network = ipaddress.ip_network(target, strict=False)
                normalized = str(network)
                return True, normalized, "cidr"
            except ValueError:
                pass

        # Step 3: Try domain name
        domain = target.lower()
        if self._is_valid_domain(domain):
            return True, domain, "domain"

        raise ValidationError(
            f"Invalid target '{target}'. "
            "Expected an IPv4/IPv6 address, CIDR range (e.g. 10.0.0.0/24), "
            "or a valid domain name (e.g. scanme.nmap.org)."
        )

    def _is_private(
        self, ip: ipaddress.IPv4Address | ipaddress.IPv6Address
    ) -> bool:
        """Return True if ip falls within any private/loopback network."""
        return any(ip in net for net in _PRIVATE_NETWORKS)

    def _is_valid_domain(self, target: str) -> bool:
        """Return True if target matches domain name syntax and contains a dot."""
        return bool(_DOMAIN_REGEX.match(target)) and "." in target

    # ── Legacy compatibility aliases ─────────────────────────────────────────

    def _is_private_ip(self, ip: str) -> bool:
        """Return True if the IP address string falls within a private range."""
        try:
            return self._is_private(ipaddress.ip_address(ip))
        except ValueError:
            return False

    def _is_valid_ip(self, ip: str) -> bool:
        """Return True if the string is a valid IPv4 or IPv6 address."""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
