import argparse
import logging
import signal
import sqlite3
import sys
import threading

import yaml

from .clients import APIError, AbuseIPDBClient, FirewallaClient
from .config import load_config
from .guard import Guard
from .state import State


def main():
    parser = argparse.ArgumentParser(description="Firewalla alarm-driven AbuseIPDB guard")
    parser.add_argument("--config", default="config.yml")
    parser.add_argument("--once", action="store_true", help="Run one poll and exit")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, stream=sys.stdout,
                        format="%(asctime)s %(levelname)s %(message)s")
    log = logging.getLogger(__name__)
    try:
        config = load_config(args.config)
        state = State(config["state"]["path"])
    except (OSError, ValueError, yaml.YAMLError, sqlite3.Error) as exc:
        # YAML errors can contain the original line, including secrets.
        log.error("Startup failed (%s). Check config values and state path permissions.",
                  type(exc).__name__)
        return 1
    fw = FirewallaClient(config["firewalla"], config["rules"]["dry_run"])
    abuse = AbuseIPDBClient(config["abuseipdb"])
    guard = Guard(config, fw, abuse, state)
    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    log.info("Starting mode=%s", "dry-run" if config["rules"]["dry_run"] else "live")
    try:
        while not stop.is_set():
            try:
                success = guard.poll_once()
            except APIError as exc:
                log.error("Poll failed; retry next poll: %s", exc)
                success = False
            if args.once:
                return 0 if success else 1
            stop.wait(config["rules"]["poll_interval_seconds"])
    except sqlite3.Error:
        log.error("SQLite failure; stopping to preserve processing state")
        return 1
    finally:
        fw.session.close()
        abuse.session.close()
        state.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
