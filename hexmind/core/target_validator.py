"""Target validation: checks IP/domain format and scope restrictions."""

import ipaddress
import re


class TargetValidator:
    """Validates scan targets against format rules and scope restrictions."""

    def validate(
        self, target: str, allow_private: bool = False
    ) -> tuple[bool, str, str]:
        """Validate target string.

        Returns (is_valid, target_type, error_message).
        target_type is one of 'ip', 'domain', 'cidr'.
        error_message is empty string on success.
        """
        raise NotImplementedError("TODO: implement")

    def _is_private_ip(self, ip: str) -> bool:
        """Return True if the IP address falls within an RFC-1918 private range."""
        raise NotImplementedError("TODO: implement")

    def _is_valid_domain(self, domain: str) -> bool:
        """Return True if the string is a syntactically valid domain name."""
        raise NotImplementedError("TODO: implement")

    def _is_valid_ip(self, ip: str) -> bool:
        """Return True if the string is a valid IPv4 or IPv6 address."""
        raise NotImplementedError("TODO: implement")
