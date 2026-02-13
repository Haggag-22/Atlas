"""Tests for atlas.core.telemetry — TelemetryRecorder and TelemetryReader."""

import json
import tempfile
from pathlib import Path

import pytest

from atlas.core.telemetry import TelemetryRecorder, TelemetryReader
from atlas.core.types import Layer


def test_record_event():
    rec = TelemetryRecorder(correlation_id="test-001")
    event = rec.record(
        layer=Layer.RECON,
        event_type="api_call",
        action="iam:ListUsers",
        status="success",
    )
    assert event.event_id
    assert event.correlation_id == "test-001"
    assert event.layer == "recon"
    assert rec.event_count == 1


def test_timeline():
    rec = TelemetryRecorder()
    rec.record(layer=Layer.RECON, event_type="a")
    rec.record(layer=Layer.PLANNER, event_type="b")
    rec.record(layer=Layer.EXECUTOR, event_type="c")

    timeline = rec.get_timeline()
    assert len(timeline) == 3
    assert timeline[0]["event_type"] == "a"


@pytest.mark.asyncio
async def test_flush_and_read():
    rec = TelemetryRecorder(correlation_id="flush-test")
    rec.record(layer=Layer.RECON, event_type="test_event", action="sts:GetCallerIdentity")
    rec.record(layer=Layer.PLANNER, event_type="decision", action="path_selected")

    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "telemetry.jsonl"
        count = await rec.flush_to_file(path)
        assert count == 2

        reader = TelemetryReader(path)
        events = await reader.read_all()
        assert len(events) == 2
        assert events[0]["correlation_id"] == "flush-test"


@pytest.mark.asyncio
async def test_read_by_layer():
    rec = TelemetryRecorder()
    rec.record(layer=Layer.RECON, event_type="a")
    rec.record(layer=Layer.PLANNER, event_type="b")
    rec.record(layer=Layer.RECON, event_type="c")

    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "telemetry.jsonl"
        await rec.flush_to_file(path)

        reader = TelemetryReader(path)
        recon_events = await reader.read_by_layer("recon")
        assert len(recon_events) == 2


@pytest.mark.asyncio
async def test_summary():
    rec = TelemetryRecorder()
    rec.record(layer=Layer.RECON, event_type="a", detection_cost=0.1)
    rec.record(layer=Layer.EXECUTOR, event_type="b", detection_cost=0.5, status="failure")

    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "telemetry.jsonl"
        await rec.flush_to_file(path)

        reader = TelemetryReader(path)
        summary = await reader.summary()
        assert summary["total_events"] == 2
        assert summary["total_detection_cost"] == 0.6
        assert summary["events_by_layer"]["recon"] == 1
