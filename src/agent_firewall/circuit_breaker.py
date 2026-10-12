import time
from typing import Optional, Callable, List, Tuple

class CircuitBreakerError(Exception):
    """Base exception for circuit breaker errors."""
    pass

class TokenBudgetExceededError(CircuitBreakerError):
    """Raised when token usage exceeds the configured budget."""
    pass

class CircuitBreaker:
    """
    Sliding window token budget tracker & circuit breaker.
    """

    def __init__(self, max_tokens: int = 1000, window_seconds: int = 60) -> None:
        if max_tokens <= 0:
            raise ValueError("max_tokens must be positive")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")

        self.max_tokens = int(max_tokens)
        self.window_seconds = int(window_seconds)
        self._history: List[Tuple[float, int]] = []
        self._tripped = False
        self._current_usage = 0
        self._trip_callback: Optional[Callable[[], None]] = None
        self._callback_fired = False

    @property
    def current_usage(self) -> int:
        self._prune_expired()
        return self._current_usage

    def is_tripped(self) -> bool:
        return self._tripped

    def set_trip_callback(self, callback: Callable[[], None]) -> None:
        self._trip_callback = callback

    def _prune_expired(self) -> None:
        now = time.time()
        cutoff = now - self.window_seconds
        valid = []
        new_usage = 0
        for ts, tokens in self._history:
            if ts >= cutoff:
                valid.append((ts, tokens))
                new_usage += tokens
        self._history = valid
        self._current_usage = new_usage
        if not self._history and self._tripped:
            self._tripped = False
            self._callback_fired = False

    def record_usage(self, tokens: int) -> None:
        if tokens < 0:
            raise ValueError("Token usage cannot be negative")
        if tokens == 0:
            return

        self._prune_expired()
        new_total = self._current_usage + tokens
        now = time.time()
        self._history.append((now, tokens))
        self._current_usage = new_total

        if new_total > self.max_tokens:
            self._tripped = True
            if self._trip_callback and not self._callback_fired:
                self._callback_fired = True
                self._trip_callback()
            raise TokenBudgetExceededError(f"Token budget exceeded: {new_total} > {self.max_tokens}")

    def check_budget(self, upcoming_tokens: int = 0) -> None:
        self._prune_expired()
        if self._tripped or (self._current_usage + upcoming_tokens > self.max_tokens):
            self._tripped = True
            raise CircuitBreakerError("Circuit breaker is open due to token budget exhaustion")

    def get_remaining_budget(self) -> int:
        if not self._history and self._current_usage > self.max_tokens:
            return 0
        self._prune_expired()
        remaining = self.max_tokens - self._current_usage
        return max(0, remaining)

    def reset(self) -> None:
        self._history.clear()
        self._current_usage = 0
        self._tripped = False
        self._callback_fired = False
