"""
atlas.executor.pace
~~~~~~~~~~~~~~~~~~~
Pace controller: enforces stealth timing between actions.

Responsibilities:
  - Minimum delay between actions
  - Randomized jitter to avoid pattern detection
  - Burst avoidance (max N calls per minute)
  - Adaptive pacing based on action noise level
"""

from __future__ import annotations

import asyncio
import random
import time
from collections import deque
from typing import Any

import structlog

from atlas.core.config import StealthConfig
from atlas.core.types import NoiseLevel

logger = structlog.get_logger(__name__)


class PaceController:
    """Enforces timing constraints for stealth execution."""

    def __init__(self, config: StealthConfig) -> None:
        self._config = config
        self._call_timestamps: deque[float] = deque()
        self._total_delay: float = 0.0

    async def wait_before_action(
        self,
        *,
        noise_level: NoiseLevel = NoiseLevel.LOW,
        pace_hint_seconds: float = 0.0,
    ) -> float:
        """Wait the appropriate amount of time before executing an action.

        Returns the actual delay in seconds.
        """
        # Calculate base delay
        if pace_hint_seconds > 0:
            base_delay = pace_hint_seconds
        else:
            base_delay = self._noise_based_delay(noise_level)

        # Enforce minimum
        base_delay = max(base_delay, self._config.min_action_delay_seconds)
        # Cap at maximum
        base_delay = min(base_delay, self._config.max_action_delay_seconds)

        # Add jitter
        jitter = base_delay * self._config.jitter_factor * random.random()
        total_delay = base_delay + jitter

        # Burst avoidance: check calls-per-minute window
        if self._config.avoid_burst:
            burst_wait = self._burst_avoidance_delay()
            total_delay = max(total_delay, burst_wait)

        if total_delay > 0:
            logger.debug(
                "pace_waiting",
                delay=f"{total_delay:.1f}s",
                noise_level=noise_level.value,
                reason="stealth_pacing",
            )
            await asyncio.sleep(total_delay)

        # Record this call
        self._call_timestamps.append(time.monotonic())
        self._total_delay += total_delay

        return total_delay

    @property
    def total_delay_seconds(self) -> float:
        return self._total_delay

    def _noise_based_delay(self, noise_level: NoiseLevel) -> float:
        """Calculate delay based on the noise level of the upcoming action."""
        delays = {
            NoiseLevel.SILENT: 0.5,
            NoiseLevel.LOW: 2.0,
            NoiseLevel.MEDIUM: 8.0,
            NoiseLevel.HIGH: 20.0,
            NoiseLevel.CRITICAL: 45.0,
        }
        return delays.get(noise_level, 5.0)

    def _burst_avoidance_delay(self) -> float:
        """Calculate additional delay to avoid exceeding calls-per-minute limit."""
        now = time.monotonic()
        window_start = now - 60.0

        # Remove timestamps outside the 1-minute window
        while self._call_timestamps and self._call_timestamps[0] < window_start:
            self._call_timestamps.popleft()

        calls_in_window = len(self._call_timestamps)
        max_calls = self._config.max_api_calls_per_minute

        if calls_in_window >= max_calls:
            # Wait until the oldest call falls out of the window
            oldest = self._call_timestamps[0]
            wait_time = 60.0 - (now - oldest) + 1.0
            logger.debug(
                "burst_avoidance",
                calls_in_window=calls_in_window,
                max_calls=max_calls,
                wait=f"{wait_time:.1f}s",
            )
            return max(0.0, wait_time)

        return 0.0
