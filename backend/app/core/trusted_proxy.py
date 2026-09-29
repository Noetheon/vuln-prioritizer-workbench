"""Decide whether a direct peer is one of the operator's trusted reverse proxies."""

from __future__ import annotations

from ipaddress import IPv4Address, IPv6Address, ip_address, ip_network


def is_trusted_proxy_host(host: str, trusted_proxy_cidrs: tuple[str, ...]) -> bool:
    """Return whether ``host`` falls inside one of the configured proxy networks."""
    if not trusted_proxy_cidrs:
        return False
    try:
        host_ip: IPv4Address | IPv6Address = ip_address(host)
    except ValueError:
        return False
    if isinstance(host_ip, IPv6Address) and host_ip.ipv4_mapped is not None:
        # Dual-stack listeners report IPv4 peers as ::ffff:a.b.c.d.
        host_ip = host_ip.ipv4_mapped
    for cidr in trusted_proxy_cidrs:
        try:
            if host_ip in ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False
