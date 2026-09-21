"""Pure alarm matching, conservative remote IP extraction and decisions."""
from ipaddress import ip_address, ip_network
import re


def normalize(text: str) -> str:
    return " ".join(re.sub(r"[_-]+", " ", text.casefold()).split())


def matches_alarm(alarm: dict, keywords: list[str]) -> bool:
    # MSP uses a numeric enum; its message need not contain the type name.
    labels = ["abnormal upload"] if alarm.get("type") == 2 else []
    labels += [alarm[k] for k in ("type", "typeName", "alarmType", "title", "message")
               if isinstance(alarm.get(k), str)]
    return any(normalize(k) in normalize(label) for k in keywords for label in labels)


def extract_remote_ips(alarm: dict) -> set[str]:
    """Accept IP literals in remote/destination fields, never arbitrary prose.

    Supports remote.ip, remoteIP, destination.address, dst_ip, p.dest.ip,
    and those same fields inside nested objects/lists. Ambiguous generic IPs
    and local/device/WAN/source subtrees are deliberately ignored.
    """
    found = set()
    remote_keys = {"remote", "destination", "dest", "dst"}
    address_keys = {"ip", "ips", "address", "addresses", "ipaddress", "ipaddresses"}
    local_keys = {"device", "local", "source", "src", "wan", "network"}

    def visit(value, remote=False, address=False):
        if isinstance(value, dict):
            for key, child in value.items():
                parts = re.sub(r"([a-z])([A-Z])", r"\1_\2", str(key)).lower()
                tokens = [p for p in re.split(r"[._-]+", parts) if p]
                if any(p in local_keys for p in tokens):
                    continue
                compact = "".join(tokens)
                explicit = compact in {r + a for r in remote_keys for a in address_keys}
                is_remote = remote or any(p in remote_keys for p in tokens) or explicit
                is_address = explicit or (bool(tokens) and tokens[-1] in address_keys)
                visit(child, is_remote, is_address)
        elif isinstance(value, list):
            for child in value:
                visit(child, remote, address)
        elif isinstance(value, str) and remote and address:
            try:
                if "%" not in value:  # Scoped IPv6 is not a public remote endpoint.
                    found.add(str(ip_address(value.strip())))
            except ValueError:
                pass

    visit(alarm)
    return found


class IPFilter:
    def __init__(self, allowlist: dict):
        self.ips = {ip_address(ip) for ip in allowlist.get("ips", [])}
        self.networks = [ip_network(cidr) for cidr in allowlist.get("cidrs", [])]

    def skip_reason(self, value: str) -> str | None:
        try:
            ip = ip_address(value)
        except ValueError:
            return "invalid IP"
        if (not ip.is_global or ip.is_private or ip.is_loopback or ip.is_multicast
                or ip.is_reserved or ip.is_link_local or ip.is_unspecified
                or getattr(ip, "ipv4_mapped", None) is not None):
            return "non-public or special-use IP"
        if ip in self.ips or any(ip in network for network in self.networks):
            return "allowlisted IP"
        return None


def decision(score: int, threshold: int, dry_run: bool) -> str:
    if type(score) is not int or not 0 <= score <= 100:
        raise ValueError("invalid abuseConfidenceScore")
    return ("would block" if dry_run else "block") if score >= threshold else "no action"
