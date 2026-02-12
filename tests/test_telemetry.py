"""Tests for telemetry recorder."""

from pathlib import Path

import pytest

from atlas.telemetry.recorder import TelemetryRecorder, get_recorder, set_recorder


def test_recorder_record_and_get_events() -> None:
    r = TelemetryRecorder()
    r.record("test_actor", "iam:ListUsers", service="iam", result="success")
    events = r.get_events()
    assert len(events) == 1
    assert events[0].actor == "test_actor"
    assert events[0].aws_api == "iam:ListUsers"


def test_recorder_timeline_dict() -> None:
    r = TelemetryRecorder()
    r.record("actor", "s3:ListBuckets")
    timeline = r.get_timeline_dict()
    assert len(timeline) == 1
    assert timeline[0]["actor"] == "actor"


def test_recorder_clear() -> None:
    r = TelemetryRecorder()
    r.record("a", "api")
    r.clear()
    assert len(r.get_events()) == 0


def test_recorder_disabled() -> None:
    r = TelemetryRecorder()
    r.set_enabled(False)
    r.record("a", "api")
    assert len(r.get_events()) == 0
