"""Network safety guards for fetching from the local box (see SAFETY.md).

Layer 1 (here): resolve DNS ourselves via public resolvers, refuse any address that is not
globally routable, and connect only to that pinned address. Layer 2 is the nftables egress
firewall inside the fetcher container (docker/fetcher-entrypoint.sh).
"""

from __future__ import annotations

import ipaddress
import socket

import dns.message
import dns.query
import dns.rdataclass
import dns.rdatatype
import dns.resolver

from . import config


class UnsafeTarget(Exception):
    """Raised when a destination must not be contacted."""


def _resolver() -> dns.resolver.Resolver:
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = list(config.load()["safety"]["resolvers"])
    r.lifetime = 5
    return r


def is_public(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return addr.is_global and not addr.is_multicast and not addr.is_reserved


def resolve_public(host: str) -> str:
    """Return one public IPv4 address for host, or raise UnsafeTarget.

    Every resolved address must be public: a name that resolves to any private address
    (a common DNS-rebinding trick) is refused outright.
    """
    try:
        ipaddress.ip_address(host)
        raise UnsafeTarget(f"literal IP hosts are not fetched: {host}")
    except ValueError:
        pass
    try:
        answers = [a.to_text() for a in _resolver().resolve(host, "A")]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout) as e:
        raise UnsafeTarget(f"dns: {type(e).__name__}") from e
    if not answers:
        raise UnsafeTarget("dns: no A records")
    bad = [a for a in answers if not is_public(a)]
    if bad:
        raise UnsafeTarget(f"non-public address(es) {bad} for {host}")
    return answers[0]


def lookup_ns(domain: str) -> list[str]:
    try:
        return sorted(a.to_text().rstrip(".").lower() for a in _resolver().resolve(domain, "NS"))
    except Exception:
        return []


def asn_for_ip(ip: str) -> dict:
    """Team Cymru origin lookup over DNS: {'asn': 64500, 'prefix': ..., 'cc': ...}."""
    rev = ".".join(reversed(ip.split(".")))
    try:
        txt = _resolver().resolve(f"{rev}.origin.asn.cymru.com", "TXT")[0].to_text().strip('"')
    except Exception:
        return {}
    parts = [p.strip() for p in txt.split("|")]
    asn = parts[0].split()[0] if parts and parts[0] else ""
    return {
        "asn": int(asn) if asn.isdigit() else None,
        "prefix": parts[1] if len(parts) > 1 else None,
        "cc": parts[2] if len(parts) > 2 else None,
    }


def public_egress_ip() -> str:
    """Ask Cloudflare's resolver which IP our DNS query came from (whoami.cloudflare CH TXT)."""
    q = dns.message.make_query("whoami.cloudflare", dns.rdatatype.TXT, dns.rdataclass.CH)
    resp = dns.query.udp(q, "1.1.1.1", timeout=5)
    for rrset in resp.answer:
        for rr in rrset:
            return rr.to_text().strip('"')
    raise RuntimeError("could not determine egress IP")


def check_egress() -> dict:
    """Raise UnsafeTarget unless the box is on an allowed network."""
    ip = public_egress_ip()
    info = asn_for_ip(ip)
    allowed = config.load()["safety"]["allowed_egress_asns"]
    info["ip"] = ip
    if info.get("asn") not in allowed:
        raise UnsafeTarget(f"egress ASN {info.get('asn')} ({ip}) not in allowed_egress_asns {allowed}")
    return info


def probe_private_blocked(timeout: float = 2.0) -> dict[str, bool]:
    """Try raw TCP connects to private ranges; True means the firewall blocked it (good)."""
    targets = {
        "lan-gateway": ("192.168.1.1", 80),
        "docker-host": ("172.17.0.1", 80),
        "tailscale": ("100.100.100.100", 80),
        "metadata": ("169.254.169.254", 80),
    }
    out = {}
    for name, addr in targets.items():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect(addr)
            out[name] = False
        except ConnectionRefusedError:
            out[name] = False  # reached the host (RST) -> not blocked
        except OSError:
            out[name] = True
        finally:
            s.close()
    return out
