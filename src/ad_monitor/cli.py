import argparse
import json
from dataclasses import asdict
from pathlib import Path

from ad_monitor.detect import detect


def main() -> None:
    parser = argparse.ArgumentParser(description="Detect high-value AD events in JSONL.")
    parser.add_argument("events", type=Path)
    args = parser.parse_args()

    records = [
        json.loads(line)
        for line in args.events.read_text(encoding="utf-8-sig").splitlines()
        if line.strip()
    ]
    print(json.dumps([asdict(alert) for alert in detect(records)], indent=2))


if __name__ == "__main__":
    main()
