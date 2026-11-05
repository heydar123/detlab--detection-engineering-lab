"""Shared data structures and small I/O helpers."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
TS_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def parse_ts(ts: str) -> float:
    return datetime.strptime(ts, TS_FORMAT).replace(tzinfo=timezone.utc).timestamp()


def fmt_ts(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime(TS_FORMAT)


@dataclass
class Alert:
    rule_id: str
    title: str
    severity: str
    tactic: str
    technique: str
    entity: dict
    first_t: float
    last_t: float
    event_ids: list
    summary: str = ""
    alert_id: str = ""
    fired_t: float = 0.0  # when the rule actually fired: the time of the event that triggered it

    @property
    def first_ts(self) -> str:
        return fmt_ts(self.first_t)

    @property
    def last_ts(self) -> str:
        return fmt_ts(self.last_t)

    @property
    def fired_ts(self) -> str:
        return fmt_ts(self.fired_t)

    def to_dict(self) -> dict:
        return {
            "alert_id": self.alert_id,
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "tactic": self.tactic,
            "technique": self.technique,
            "entity": self.entity,
            "first_ts": self.first_ts,
            "last_ts": self.last_ts,
            "fired_ts": self.fired_ts,
            "event_ids": self.event_ids,
            "summary": self.summary,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Alert":
        return cls(
            rule_id=d["rule_id"],
            title=d["title"],
            severity=d["severity"],
            tactic=d["tactic"],
            technique=d["technique"],
            entity=d["entity"],
            first_t=parse_ts(d["first_ts"]),
            last_t=parse_ts(d["last_ts"]),
            event_ids=list(d["event_ids"]),
            summary=d.get("summary", ""),
            alert_id=d.get("alert_id", ""),
            fired_t=parse_ts(d["fired_ts"]) if "fired_ts" in d else parse_ts(d["first_ts"]),
        )


def prepare_events(events: list[dict]) -> list[dict]:
    """Add the parsed epoch time (`_t`) used internally by the engine."""
    for ev in events:
        ev["_t"] = parse_ts(ev["ts"])
    return events


def read_jsonl(path: str | Path) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def write_jsonl(path: str | Path, rows: list[dict]) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, separators=(",", ":")) + "\n")


def load_events(path: str | Path) -> list[dict]:
    return prepare_events(read_jsonl(path))
