"""All API paths, request payloads and response adapters live here.

References: https://docs.firewalla.net/api-reference/ and https://docs.abuseipdb.com/
"""
from ipaddress import ip_address
import time
from urllib.parse import quote

import requests

ALARMS = "/v2/alarms"
ALARM = "/v2/alarms/{gid}/{aid}"
ALARM_ARCHIVE = "/v2/alarms/{gid}/{aid}/archive"
TARGET_LISTS = "/v2/target-lists"
TARGET_LIST = "/v2/target-lists/{id}"
ABUSE_CHECK = "https://api.abuseipdb.com/api/v2/check"
TIMEOUT = (10, 30)


class APIError(RuntimeError):
    """Sanitized API failure safe to log without credentials or response bodies."""


def request_json(session, method, url, expect_json=True, **kwargs):
    try:
        response = session.request(method, url, timeout=TIMEOUT, allow_redirects=False, **kwargs)
        if not 200 <= response.status_code < 300:
            raise APIError(f"{method} failed: HTTP {response.status_code}")
        return response.json() if expect_json else None
    except requests.RequestException as exc:
        raise APIError(f"{method} failed: {type(exc).__name__}") from None
    except ValueError:
        raise APIError(f"{method} returned invalid JSON") from None


def require_dict(value):
    if not isinstance(value, dict):
        raise APIError("Expected a JSON object")
    return value


class FirewallaClient:
    def __init__(self, config: dict, dry_run=True, session=None):
        self.base_url = "https://" + config["msp_domain"]
        self.gid = config["box_gid"]
        self.name = config["target_list_name"]
        self.dry_run = dry_run
        self.session = session or requests.Session()
        self.session.headers.update({"Authorization": "Token " + config["token"],
                                     "Accept": "application/json"})

    def _request(self, method, path, **kwargs):
        if self.dry_run and method != "GET":
            raise APIError("Firewalla writes are disabled in dry-run mode")
        return request_json(self.session, method, self.base_url + path, **kwargs)

    def list_recent_alarms(self, lookback_hours=24):
        params = {"query": f"box.id:{self.gid} ts:>={int(time.time() - lookback_hours * 3600)}",
                  "limit": 500, "sortBy": "ts:desc"}
        seen_cursors = set()
        while True:
            page = require_dict(self._request("GET", ALARMS, params=dict(params)))
            rows = page.get("results")
            if not isinstance(rows, list):
                raise APIError("Alarm response lacks results array")
            for alarm in rows:
                require_dict(alarm)
                if alarm.get("gid") != self.gid:
                    raise APIError("Alarm response contains a missing or unexpected box ID")
                yield alarm
            cursor = page.get("next_cursor")
            if not cursor:
                break
            if not isinstance(cursor, str) or cursor in seen_cursors:
                raise APIError("Invalid or repeated alarm pagination cursor")
            seen_cursors.add(cursor)
            params["cursor"] = cursor

    def get_alarm(self, aid: str):
        path = ALARM.format(gid=quote(self.gid, safe=""), aid=quote(str(aid), safe=""))
        alarm = require_dict(self._request("GET", path))
        if alarm.get("gid") != self.gid or str(alarm.get("aid")) != str(aid):
            raise APIError("Alarm details identity mismatch")
        return alarm

    def archive_alarm(self, aid: str):
        path = ALARM_ARCHIVE.format(gid=quote(self.gid, safe=""), aid=quote(str(aid), safe=""))
        # The archive endpoint documents success by HTTP status, without a JSON body.
        self._request("POST", path, expect_json=False)

    def target_list_contains(self, ip: str) -> bool:
        rows = self._request("GET", TARGET_LISTS, params={"owner": self.gid})
        if not isinstance(rows, list):
            raise APIError("Target list response must be an array")
        matches = [row for row in rows if require_dict(row).get("name") == self.name
                   and row.get("owner") == self.gid]
        if len(matches) > 1:
            raise APIError("Multiple target lists have the configured name and owner")
        if not matches:
            return False
        list_id = matches[0].get("id")
        if not isinstance(list_id, str) or not list_id:
            raise APIError("Target list lacks ID")
        current = require_dict(self._request("GET", TARGET_LIST.format(id=quote(list_id, safe=""))))
        if current.get("owner") != self.gid or current.get("name") != self.name:
            raise APIError("Target list ownership/name mismatch")
        if not isinstance(current.get("targets"), list):
            raise APIError("Target list lacks a valid targets array")
        return str(ip_address(ip)) in current["targets"]

    def find_or_create_target_list(self, initial_ip: str | None = None):
        # Box-owned lists avoid accidentally changing another box's/global policy.
        rows = self._request("GET", TARGET_LISTS, params={"owner": self.gid})
        if not isinstance(rows, list):
            raise APIError("Target list response must be an array")
        matches = [row for row in rows if require_dict(row).get("name") == self.name
                   and row.get("owner") == self.gid]
        if len(matches) > 1:
            raise APIError("Multiple target lists have the configured name and owner")
        if matches:
            result = matches[0]
        else:
            if initial_ip is None:
                raise APIError("Firewalla requires at least one target to create a list; "
                               "a live matching alarm must supply the first IP")
            initial_ip = str(ip_address(initial_ip))
            result = require_dict(self._request(
                "POST", TARGET_LISTS,
                json={"name": self.name, "owner": self.gid, "targets": [initial_ip]}))
        if not isinstance(result.get("id"), str) or not result["id"]:
            raise APIError("Target list lacks ID")
        return result["id"]

    def add_ip_to_target_list(self, ip: str):
        ip = str(ip_address(ip))
        list_id = self.find_or_create_target_list(initial_ip=ip)
        path = TARGET_LIST.format(id=quote(list_id, safe=""))
        current = require_dict(self._request("GET", path))
        if current.get("owner") != self.gid or current.get("name") != self.name:
            raise APIError("Target list ownership/name mismatch")
        targets = current.get("targets")
        if not isinstance(targets, list) or any(not isinstance(t, str) for t in targets):
            raise APIError("Target list lacks a valid targets array; refusing replacement")
        if ip not in targets:
            updated = require_dict(self._request("PATCH", path, json={"targets": targets + [ip]}))
            if not isinstance(updated.get("targets"), list) or ip not in updated["targets"]:
                raise APIError("Target list update did not confirm IP membership")
        return list_id


class AbuseIPDBClient:
    def __init__(self, config: dict, session=None):
        self.max_age = config["max_age_days"]
        self.session = session or requests.Session()
        self.session.headers.update({"Key": config["api_key"], "Accept": "application/json"})

    def check_ip(self, ip: str) -> dict:
        response = require_dict(request_json(self.session, "GET", ABUSE_CHECK,
            params={"ipAddress": ip, "maxAgeInDays": self.max_age}))
        data = require_dict(response.get("data"))
        try:
            returned_ip = data.get("ipAddress")
            if not isinstance(returned_ip, str) or ip_address(returned_ip) != ip_address(ip):
                raise ValueError
        except ValueError:
            raise APIError("AbuseIPDB returned an unexpected IP address") from None
        score = data.get("abuseConfidenceScore")
        if type(score) is not int or not 0 <= score <= 100:
            raise APIError("AbuseIPDB returned an invalid abuseConfidenceScore")
        return {key: data.get(key) for key in (
            "ipAddress", "abuseConfidenceScore", "totalReports", "lastReportedAt",
            "countryCode", "isp", "usageType", "isPublic")}
