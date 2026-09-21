import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

from firewalla_abuse_guard.clients import APIError, AbuseIPDBClient, FirewallaClient
from firewalla_abuse_guard.config import load_config
from firewalla_abuse_guard.guard import Guard
from firewalla_abuse_guard.logic import IPFilter, decision, extract_remote_ips, matches_alarm
from firewalla_abuse_guard.state import State


def config():
    return {
        "firewalla": {"msp_domain": "example.firewalla.net", "token": "test",
                      "box_gid": "box-1", "target_list_name": "Test"},
        "abuseipdb": {"api_key": "test", "max_age_days": 30, "block_threshold": 90},
        "rules": {"dry_run": True, "poll_interval_seconds": 300, "lookback_hours": 24,
                  "ip_cache_hours": 24, "alarm_keywords": ["abnormal upload"]},
        "allowlist": {"ips": [], "cidrs": []},
    }


def alarm(aid=1):
    return {"aid": aid, "gid": "box-1", "type": 2, "remote": {"ip": "8.8.8.8"}}


class LogicTests(unittest.TestCase):
    def test_nested_extraction(self):
        data = {"payload": [{"remote": {"ip": "8.8.8.8"}},
                            {"p.dest.ip": "2001:4860:4860::8888"},
                            {"destination": {"addresses": ["1.1.1.1", "bad"]}},
                            {"dst_ip": "8.8.4.4"}, {"remoteIP": "8.8.8.8"}]}
        self.assertEqual(extract_remote_ips(data),
                         {"8.8.8.8", "1.1.1.1", "8.8.4.4", "2001:4860:4860::8888"})

    def test_never_extract_ambiguous_or_local_addresses(self):
        data = {"ip": "8.8.8.8", "device": {"ip": "1.1.1.1"},
                "wan": {"remoteIP": "8.8.4.4"}, "message": "upload to 9.9.9.9",
                "remote": {"domain": "1.0.0.1", "ip": "https://8.8.8.8/path"},
                "source_ip": "8.8.8.8"}
        self.assertEqual(extract_remote_ips(data), set())

    def test_special_use_and_allowlist(self):
        check = IPFilter({"ips": ["8.8.8.8"], "cidrs": ["1.1.1.0/24", "2606:4700::/32"]})
        for ip in ("10.0.0.1", "172.16.0.1", "192.168.1.1", "127.0.0.1", "169.254.1.1",
                   "224.0.0.1", "240.0.0.1", "0.0.0.0", "100.64.0.1", "192.0.2.1",
                   "::1", "::", "fe80::1", "fc00::1", "ff02::1", "2001:db8::1",
                   "::ffff:8.8.8.8", "8.8.8.8", "1.1.1.1", "2606:4700:4700::1111", "bad"):
            with self.subTest(ip=ip):
                self.assertIsNotNone(check.skip_reason(ip))
        self.assertIsNone(check.skip_reason("9.9.9.9"))
        self.assertIsNone(check.skip_reason("2001:4860:4860::8888"))

    def test_threshold(self):
        self.assertEqual(decision(89, 90, False), "no action")
        self.assertEqual(decision(90, 90, True), "would block")
        self.assertEqual(decision(90, 90, False), "block")
        self.assertEqual(decision(100, 90, False), "block")
        for score in (True, "90", -1, 101, None):
            with self.assertRaises(ValueError):
                decision(score, 90, False)

    def test_matching(self):
        self.assertTrue(matches_alarm({"type": 2}, ["abnormal upload"]))
        self.assertTrue(matches_alarm({"type": "ALARM_ABNORMAL_UPLOAD"}, ["Abnormal Upload"]))
        self.assertFalse(matches_alarm({"type": 16}, ["abnormal upload"]))
        self.assertFalse(matches_alarm({"remote": {"domain": "abnormal upload"}}, ["abnormal upload"]))


class StateTests(unittest.TestCase):
    def test_persistence_scope_and_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "state.sqlite3")
            state = State(path)
            self.assertFalse(state.processed("dry", "1"))
            state.mark_processed("dry", "1")
            state.mark_processed("dry", "1")
            state.save_check("8.8.8.8", 30, {"abuseConfidenceScore": 90})
            state.mark_blocked("box", "8.8.8.8", "1", "TL-1")
            state.close()
            state = State(path)
            self.addCleanup(state.close)
            self.assertTrue(state.processed("dry", "1"))
            self.assertFalse(state.processed("live", "1"))
            self.assertTrue(state.blocked("box", "8.8.8.8"))
            self.assertFalse(state.blocked("other-box", "8.8.8.8"))
            self.assertEqual(state.cached_check("8.8.8.8", 30, 3600)["abuseConfidenceScore"], 90)
            self.assertIsNone(state.cached_check("8.8.8.8", 60, 3600))
            self.assertIsNone(state.cached_check("8.8.8.8", 30, 0))


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.state = State(":memory:")
        self.addCleanup(self.state.close)
        self.config = config()
        self.fw, self.abuse = Mock(), Mock()
        self.abuse.check_ip.return_value = {"abuseConfidenceScore": 90}
        self.fw.add_ip_to_target_list.return_value = "TL-1"
        self.fw.target_list_contains.return_value = True
        self.guard = Guard(self.config, self.fw, self.abuse, self.state)

    def test_dry_run_dedup_and_live_transition(self):
        self.guard.process_alarm(alarm())
        self.guard.process_alarm(alarm())
        self.guard.process_alarm(alarm(2))
        self.abuse.check_ip.assert_called_once_with("8.8.8.8")
        self.fw.add_ip_to_target_list.assert_not_called()
        self.fw.archive_alarm.assert_not_called()
        self.assertFalse(self.state.blocked(self.guard.block_scope, "8.8.8.8"))
        live = copy.deepcopy(self.config)
        live["rules"]["dry_run"] = False
        guard = Guard(live, self.fw, self.abuse, self.state)
        guard.process_alarm(alarm())
        guard.process_alarm(alarm(3))
        self.fw.add_ip_to_target_list.assert_called_once_with("8.8.8.8")
        self.assertTrue(self.state.blocked(guard.block_scope, "8.8.8.8"))
        self.assertEqual(self.fw.archive_alarm.call_count, 2)

    def test_failed_write_remains_retryable(self):
        self.config["rules"]["dry_run"] = False
        guard = Guard(self.config, self.fw, self.abuse, self.state)
        self.fw.add_ip_to_target_list.side_effect = APIError("failed")
        with self.assertRaises(APIError):
            guard.process_alarm(alarm())
        self.assertFalse(self.state.processed(guard.scope, "1"))
        self.assertFalse(self.state.blocked(guard.block_scope, "8.8.8.8"))
        self.fw.archive_alarm.assert_not_called()
        self.fw.add_ip_to_target_list.side_effect = None
        guard.process_alarm(alarm())
        self.assertTrue(self.state.processed(guard.scope, "1"))
        self.abuse.check_ip.assert_called_once()

    def test_no_api_action_without_matching_public_remote(self):
        for row in ({**alarm(), "type": 5}, {**alarm(2), "remote": {"ip": "10.0.0.1"}}):
            self.guard.process_alarm(row)
        self.abuse.check_ip.assert_not_called()
        self.fw.add_ip_to_target_list.assert_not_called()

    def test_low_score(self):
        self.abuse.check_ip.return_value = {"abuseConfidenceScore": 89}
        self.config["rules"]["dry_run"] = False
        self.guard.process_alarm(alarm())
        self.fw.add_ip_to_target_list.assert_not_called()

    def test_details_fallback(self):
        self.fw.get_alarm.return_value = alarm()
        self.guard.process_alarm({"aid": 1, "gid": "box-1", "type": 2})
        self.fw.get_alarm.assert_called_once_with("1")
        self.abuse.check_ip.assert_called_once_with("8.8.8.8")

    def test_api_failure_stops_cycle_without_marking_processed(self):
        self.fw.list_recent_alarms.return_value = [alarm(), alarm(2)]
        self.abuse.check_ip.side_effect = APIError("HTTP 429")
        self.assertFalse(self.guard.poll_once())
        self.assertFalse(self.state.processed(self.guard.scope, "1"))
        self.abuse.check_ip.assert_called_once()

    def test_partial_alarm_retries_only_unfinished_ip(self):
        self.config["rules"]["dry_run"] = False
        guard = Guard(self.config, self.fw, self.abuse, self.state)
        row = {**alarm(), "remote": {"ips": ["1.1.1.1", "8.8.8.8"]}}
        self.fw.add_ip_to_target_list.side_effect = ["TL-1", APIError("failed")]
        with self.assertRaises(APIError):
            guard.process_alarm(row)
        self.assertTrue(self.state.blocked(guard.block_scope, "1.1.1.1"))
        self.assertFalse(self.state.processed(guard.scope, "1"))
        self.fw.add_ip_to_target_list.reset_mock(side_effect=True)
        guard.process_alarm(row)
        self.fw.add_ip_to_target_list.assert_called_once_with("8.8.8.8")

    def test_allowlist_prevents_live_write(self):
        self.config["rules"]["dry_run"] = False
        self.config["allowlist"]["ips"] = ["8.8.8.8"]
        Guard(self.config, self.fw, self.abuse, self.state).process_alarm(alarm())
        self.abuse.check_ip.assert_not_called()
        self.fw.add_ip_to_target_list.assert_not_called()
        self.fw.archive_alarm.assert_not_called()

    def test_archive_failure_retries_without_reblocking(self):
        self.config["rules"]["dry_run"] = False
        guard = Guard(self.config, self.fw, self.abuse, self.state)
        self.fw.archive_alarm.side_effect = APIError("archive failed")
        with self.assertRaises(APIError):
            guard.process_alarm(alarm())
        self.assertTrue(self.state.blocked(guard.block_scope, "8.8.8.8"))
        self.assertFalse(self.state.processed(guard.scope, "1"))
        self.fw.archive_alarm.side_effect = None
        guard.process_alarm(alarm())
        self.fw.add_ip_to_target_list.assert_called_once()
        self.fw.target_list_contains.assert_called_once_with("8.8.8.8")
        self.assertTrue(self.state.processed(guard.scope, "1"))

    def test_previously_processed_alarm_revisited_when_archiving_enabled(self):
        self.config["rules"].update(dry_run=False, archive_blocked=False)
        old = Guard(self.config, self.fw, self.abuse, self.state)
        old.process_alarm(alarm())
        self.fw.archive_alarm.assert_not_called()
        new_config = copy.deepcopy(self.config)
        new_config["rules"]["archive_blocked"] = True
        new = Guard(new_config, self.fw, self.abuse, self.state)
        new.process_alarm(alarm())
        self.fw.archive_alarm.assert_called_once_with("1")
        self.fw.add_ip_to_target_list.assert_called_once()

    def test_removed_ip_keeps_alarm_visible(self):
        self.config["rules"]["dry_run"] = False
        self.state.mark_blocked(self.guard.block_scope, "8.8.8.8", "0", "TL-1")
        self.fw.target_list_contains.return_value = False
        Guard(self.config, self.fw, self.abuse, self.state).process_alarm(alarm())
        self.fw.archive_alarm.assert_not_called()
        self.fw.add_ip_to_target_list.assert_not_called()

    def test_mixed_low_score_alarm_not_archived(self):
        self.config["rules"]["dry_run"] = False
        self.abuse.check_ip.side_effect = [{"abuseConfidenceScore": 100},
                                          {"abuseConfidenceScore": 0}]
        row = {**alarm(), "remote": {"ips": ["1.1.1.1", "8.8.8.8"]}}
        Guard(self.config, self.fw, self.abuse, self.state).process_alarm(row)
        self.fw.add_ip_to_target_list.assert_called_once_with("1.1.1.1")
        self.fw.archive_alarm.assert_not_called()

    def test_already_archived_alarm_not_archived_again(self):
        self.config["rules"]["dry_run"] = False
        Guard(self.config, self.fw, self.abuse, self.state).process_alarm({**alarm(), "status": 2})
        self.fw.archive_alarm.assert_not_called()


class ClientTests(unittest.TestCase):
    def client(self, responses, dry_run=False):
        session = Mock()
        session.headers = {}
        session.request.side_effect = [Mock(status_code=200, json=Mock(return_value=r)) for r in responses]
        return FirewallaClient(config()["firewalla"], dry_run, session), session

    def test_paginated_alarms(self):
        fw, session = self.client([{"results": [alarm()], "next_cursor": "next"},
                                   {"results": [alarm(2)], "next_cursor": None}])
        self.assertEqual(len(list(fw.list_recent_alarms())), 2)
        self.assertEqual(session.request.call_args.kwargs["params"]["cursor"], "next")
        self.assertIn("box.id:box-1", session.request.call_args.kwargs["params"]["query"])

    def test_archive_accepts_empty_success_and_is_dry_run_guarded(self):
        fw, session = self.client([None])
        session.request.side_effect = None
        session.request.return_value = Mock(status_code=200)
        session.request.return_value.json.side_effect = ValueError("empty body")
        fw.archive_alarm("1")
        self.assertEqual(session.request.call_args.args,
                         ("POST", "https://example.firewalla.net/v2/alarms/box-1/1/archive"))
        session.request.return_value.json.assert_not_called()
        fw.dry_run = True
        with self.assertRaises(APIError):
            fw.archive_alarm("1")
        self.assertEqual(session.request.call_count, 1)

    def test_membership_check_never_creates_list(self):
        fw, session = self.client([[]])
        self.assertFalse(fw.target_list_contains("8.8.8.8"))
        session.request.assert_called_once()
        target = {"id": "TL-1", "name": "Test", "owner": "box-1", "targets": ["8.8.8.8"]}
        fw, _ = self.client([[target], target])
        self.assertTrue(fw.target_list_contains("8.8.8.8"))

    def test_update_preserves_targets(self):
        target = {"id": "TL-1", "name": "Test", "owner": "box-1", "targets": ["example.org"]}
        fw, session = self.client([[target], target, {"targets": ["example.org", "8.8.8.8"]}])
        self.assertEqual(fw.add_ip_to_target_list("8.8.8.8"), "TL-1")
        self.assertEqual(session.request.call_args.args[0], "PATCH")
        self.assertEqual(session.request.call_args.kwargs["json"],
                         {"targets": ["example.org", "8.8.8.8"]})

    def test_repeated_cursor_and_wrong_box_fail(self):
        for responses in (
            [{"results": [], "next_cursor": "same"}, {"results": [], "next_cursor": "same"}],
            [{"results": [{**alarm(), "gid": "other-box"}]}],
        ):
            fw, _ = self.client(responses)
            with self.assertRaises(APIError):
                list(fw.list_recent_alarms())

    def test_create_and_existing_membership(self):
        target = {"id": "TL-1", "name": "Test", "owner": "box-1", "targets": ["8.8.8.8"]}
        fw, session = self.client([[], target, target])
        fw.add_ip_to_target_list("8.8.8.8")
        self.assertEqual([c.args[0] for c in session.request.call_args_list], ["GET", "POST", "GET"])
        self.assertEqual(session.request.call_args_list[1].kwargs["json"],
                         {"name": "Test", "owner": "box-1", "targets": ["8.8.8.8"]})

    def test_missing_list_without_initial_ip_does_not_post(self):
        fw, session = self.client([[]])
        with self.assertRaisesRegex(APIError, "at least one target"):
            fw.find_or_create_target_list()
        self.assertEqual([c.args[0] for c in session.request.call_args_list], ["GET"])

    def test_dry_run_client_refuses_mutations(self):
        fw, session = self.client([[]], dry_run=True)
        with self.assertRaises(APIError):
            fw.add_ip_to_target_list("8.8.8.8")
        self.assertEqual([c.args[0] for c in session.request.call_args_list], ["GET"])

    def test_refuses_missing_targets_and_ambiguous_lists(self):
        target = {"id": "TL-1", "name": "Test", "owner": "box-1"}
        for responses in ([[target], target], [[target, target]]):
            fw, session = self.client(responses)
            with self.assertRaises(APIError):
                fw.add_ip_to_target_list("8.8.8.8")
            self.assertTrue(all(c.args[0] == "GET" for c in session.request.call_args_list))

    def test_abuse_score_and_identity_validation(self):
        for data in ({"ipAddress": "8.8.4.4", "abuseConfidenceScore": 90},
                     {"ipAddress": "8.8.8.8", "abuseConfidenceScore": "90"},
                     {"ipAddress": "8.8.8.8", "abuseConfidenceScore": 90}):
            session = Mock(headers={})
            session.request.return_value = Mock(status_code=200, json=lambda: {"data": data})
            client = AbuseIPDBClient(config()["abuseipdb"], session)
            if data == {"ipAddress": "8.8.8.8", "abuseConfidenceScore": 90}:
                self.assertEqual(client.check_ip("8.8.8.8")["abuseConfidenceScore"], 90)
            else:
                with self.assertRaises(APIError):
                    client.check_ip("8.8.8.8")


class ConfigTests(unittest.TestCase):
    def test_defaults_and_invalid_boolean(self):
        import yaml
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.yml"
            value = config()
            del value["rules"]["dry_run"]
            path.write_text(yaml.safe_dump(value))
            self.assertTrue(load_config(str(path))["rules"]["dry_run"])
            value["rules"]["dry_run"] = "false"
            path.write_text(yaml.safe_dump(value))
            with self.assertRaises(ValueError):
                load_config(str(path))


if __name__ == "__main__":
    unittest.main()
