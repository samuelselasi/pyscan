import time

class Throttler:
    """Enforces a minimum delay between HTTP requests to avoid harming the target server."""

    def __init__(self, delay=0.5):
        self.delay = delay
        self._last = 0.0

    def wait(self):
        now = time.monotonic()
        elapsed = now - self._last
        if elapsed < self.delay:
            time.sleep(self.delay - elapsed)
        self._last = time.monotonic()
