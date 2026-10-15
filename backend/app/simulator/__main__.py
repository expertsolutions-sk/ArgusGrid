"""Command line: python -m app.simulator --speed 10 [--base-url http://127.0.0.1:8000] [--creds file] [--loop]"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from app.core.config import BACKEND_DIR
from app.simulator.runner import http_poster, load_credentials, run
from app.simulator.scenario import END_TIME


def main() -> int:
    parser = argparse.ArgumentParser(description="Hybrid attack simulator for the Kestrel Ridge demo site")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--creds", default=str(BACKEND_DIR / "data" / "demo-devices.txt"))
    parser.add_argument("--speed", type=float, default=1.0, help="simulated seconds per real second")
    parser.add_argument("--until", type=float, default=None, help="stop at this simulated second")
    parser.add_argument("--loop", action="store_true", help="repeat the scenario until interrupted")
    args = parser.parse_args()

    path = Path(args.creds)
    if not path.is_file():
        print(f"Device credentials not found: {path}. Run: python -m app.tools.demo_data create", file=sys.stderr)
        return 2
    keys = load_credentials(path)
    poster = http_poster(args.base_url)
    print(f"Simulating {END_TIME:.0f} s of scenario at x{args.speed:g} against {args.base_url} ({len(keys)} devices)")
    try:
        while True:
            stats = run(keys, poster, speed=args.speed, until=args.until,
                        on_progress=lambda t, n: print(f"\r  t={t:6.0f}s events={n}", end="", flush=True))
            print(f"\nDone: {stats.sent_events} events in {stats.requests} requests, "
                  f"{stats.failed_requests} failed requests.")
            if not args.loop:
                return 0 if stats.failed_requests == 0 else 1
            time.sleep(2)
    except KeyboardInterrupt:
        print("\nStopped.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
