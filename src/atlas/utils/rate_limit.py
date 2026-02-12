"""Rate limiting and jitter for AWS API calls."""

import random
import time
from functools import wraps
from typing import Callable, TypeVar

F = TypeVar("F", bound=Callable[..., object])


def with_rate_limit_and_jitter(
    calls_per_second: float = 5.0,
    jitter_seconds: float = 0.5,
) -> Callable[[F], F]:
    """Decorator to rate-limit and add jitter to a function."""

    def decorator(func: F) -> F:
        last_called = [0.0]

        @wraps(func)
        def wrapper(*args: object, **kwargs: object) -> object:
            now = time.monotonic()
            min_interval = 1.0 / calls_per_second
            elapsed = now - last_called[0]
            sleep_time = max(0, min_interval - elapsed)
            if jitter_seconds > 0:
                sleep_time += random.uniform(0, jitter_seconds)
            if sleep_time > 0:
                time.sleep(sleep_time)
            last_called[0] = time.monotonic()
            return func(*args, **kwargs)

        return wrapper  # type: ignore[return-value]

    return decorator
