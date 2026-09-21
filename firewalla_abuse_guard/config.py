"""Load and validate configuration before any API calls."""
from ipaddress import ip_address, ip_network
from pathlib import Path
import re

import yaml


def load_config(path: str) -> dict:
    with Path(path).open() as handle:
        config = yaml.safe_load(handle)
    if not isinstance(config, dict):
        raise ValueError("config must be a mapping")
    for section in ("firewalla", "abuseipdb", "rules", "allowlist", "state"):
        config.setdefault(section, {})
        if not isinstance(config[section], dict):
            raise ValueError(f"{section} must be a mapping")
    fw, abuse, rules = (config[k] for k in ("firewalla", "abuseipdb", "rules"))
    for section, keys in ((fw, ("msp_domain", "token", "box_gid", "target_list_name")),
                          (abuse, ("api_key",))):
        for key in keys:
            if not isinstance(section.get(key), str) or not section[key].strip():
                raise ValueError(f"{key} must be a nonempty string")
    if not re.fullmatch(r"[a-zA-Z0-9.-]+", fw["msp_domain"]):
        raise ValueError("msp_domain must be a hostname without a scheme or path")
    if not re.fullmatch(r"[a-zA-Z0-9-]+", fw["box_gid"]):
        raise ValueError("box_gid must contain only letters, numbers and hyphens")
    rules.setdefault("dry_run", True)
    if type(rules["dry_run"]) is not bool:
        raise ValueError("dry_run must be a YAML boolean")
    rules.setdefault("archive_blocked", True)
    if type(rules["archive_blocked"]) is not bool:
        raise ValueError("archive_blocked must be a YAML boolean")
    for section, key, default, low, high in (
        (abuse, "max_age_days", 30, 1, 365),
        (abuse, "block_threshold", 90, 0, 100),
        (rules, "poll_interval_seconds", 300, 1, 86400),
        (rules, "lookback_hours", 24, 1, 720),
        (rules, "ip_cache_hours", 24, 1, 720),
    ):
        section.setdefault(key, default)
        if type(section[key]) is not int or not low <= section[key] <= high:
            raise ValueError(f"{key} must be an integer in {low}..{high}")
    rules.setdefault("alarm_keywords", ["abnormal upload"])
    keywords = rules["alarm_keywords"]
    if not isinstance(keywords, list) or not keywords or any(
        not isinstance(k, str) or not k.strip() for k in keywords
    ):
        raise ValueError("alarm_keywords must be a nonempty list of nonempty strings")
    for key, parser in (("ips", ip_address), ("cidrs", ip_network)):
        values = config["allowlist"].setdefault(key, [])
        if not isinstance(values, list):
            raise ValueError(f"allowlist.{key} must be a list")
        for value in values:
            if not isinstance(value, str):
                raise ValueError(f"allowlist.{key} entries must be strings")
            parser(value)
    config["state"].setdefault("path", "data/state.sqlite3")
    if not isinstance(config["state"]["path"], str) or not config["state"]["path"]:
        raise ValueError("state.path must be a nonempty string")
    return config
