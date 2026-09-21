"""Polling orchestration. Only a matching Firewalla alarm can trigger a write."""
import hashlib
import json
import logging

from .clients import APIError
from .logic import IPFilter, decision, extract_remote_ips, matches_alarm

log = logging.getLogger(__name__)


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


class Guard:
    def __init__(self, config, firewalla, abuseipdb, state):
        self.config, self.firewalla, self.abuseipdb, self.state = config, firewalla, abuseipdb, state
        self.rules = config["rules"]
        self.archive_blocked = self.rules.get("archive_blocked", True)
        self.filter = IPFilter(config["allowlist"])
        fw = config["firewalla"]
        self.block_scope = fingerprint([fw["msp_domain"], fw["box_gid"], fw["target_list_name"]])
        # Policy changes and dry-run -> live deserve a fresh alarm decision.
        self.scope = fingerprint([self.block_scope, config["allowlist"],
                                  {**self.rules, "archive_blocked": self.archive_blocked},
                                  config["abuseipdb"]["block_threshold"],
                                  config["abuseipdb"]["max_age_days"]])

    def process_alarm(self, alarm):
        if alarm.get("gid") != self.config["firewalla"]["box_gid"]:
            raise APIError("Alarm box mismatch")
        aid = alarm.get("aid")
        if isinstance(aid, bool) or not isinstance(aid, (str, int)) or str(aid) == "":
            raise APIError("Alarm lacks a valid ID")
        aid = str(aid)
        if self.state.processed(self.scope, aid):
            return
        matches = matches_alarm(alarm, self.rules["alarm_keywords"])
        ips = extract_remote_ips(alarm) if matches else set()
        if (matches and not ips) or not any(k in alarm for k in ("type", "message", "title")):
            alarm = self.firewalla.get_alarm(aid)
            matches = matches_alarm(alarm, self.rules["alarm_keywords"])
            ips = extract_remote_ips(alarm) if matches else set()
        if not matches:
            log.info("alarm=%s no action: keyword mismatch", aid)
        elif not ips:
            log.warning("alarm=%s no action: no recognized remote IP fields", aid)
        fully_blocked = bool(ips)
        for ip in sorted(ips):
            reason = self.filter.skip_reason(ip)
            if reason:
                fully_blocked = False
                log.info("alarm=%s ip=%s skip: %s", aid, ip, reason)
                continue
            if self.state.blocked(self.block_scope, ip):
                log.info("alarm=%s ip=%s no action: already added to target list", aid, ip)
                if self.archive_blocked and not self.rules["dry_run"]:
                    if not self.firewalla.target_list_contains(ip):
                        fully_blocked = False
                        log.warning("alarm=%s ip=%s keep alarm: IP no longer in target list", aid, ip)
                continue
            abuse = self.config["abuseipdb"]
            metadata = self.state.cached_check(ip, abuse["max_age_days"],
                                                self.rules["ip_cache_hours"] * 3600)
            if metadata is None:
                metadata = self.abuseipdb.check_ip(ip)
                self.state.save_check(ip, abuse["max_age_days"], metadata)
            score = metadata["abuseConfidenceScore"]
            action = decision(score, abuse["block_threshold"], self.rules["dry_run"])
            if action == "block":
                list_id = self.firewalla.add_ip_to_target_list(ip)
                self.state.mark_blocked(self.block_scope, ip, aid, list_id)
                log.info("alarm=%s ip=%s score=%s added to blocking target list", aid, ip, score)
            else:
                fully_blocked = False
                log.info("alarm=%s ip=%s score=%s %s", aid, ip, score, action)
        if (self.archive_blocked and not self.rules["dry_run"] and fully_blocked
                and alarm.get("status") not in (2, "archived")):
            self.firewalla.archive_alarm(aid)
            log.info("alarm=%s archived: remote IPs added to blocking target list", aid)
        # Exceptions above leave the alarm retryable. Already added IPs are durable.
        self.state.mark_processed(self.scope, aid)

    def poll_once(self):
        failures = 0
        for alarm in self.firewalla.list_recent_alarms(self.rules["lookback_hours"]):
            try:
                self.process_alarm(alarm)
            except APIError as exc:
                failures += 1
                log.error("Alarm processing failed; retry next poll: %s", exc)
                # Stop this cycle on API failures, including 429, to avoid hammering APIs.
                break
        log.info("Poll complete; failures=%s", failures)
        return failures == 0
