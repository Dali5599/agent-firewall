import pytest
from unittest.mock import MagicMock
from agent_firewall.circuit_breaker import CircuitBreaker, CircuitBreakerError, TokenBudgetExceededError


@pytest.fixture
def circuit_breaker() -> CircuitBreaker:
    """Fixture to provide a fresh CircuitBreaker instance for each test."""
    return CircuitBreaker(max_tokens=1000, window_seconds=60)


def test_initial_state(circuit_breaker: CircuitBreaker) -> None:
    """Test that the circuit breaker initializes with correct parameters and state."""
    assert circuit_breaker.max_tokens == 1000
    assert circuit_breaker.window_seconds == 60
    assert circuit_breaker.current_usage == 0
    assert not circuit_breaker.is_tripped()


def test_record_usage_within_budget(circuit_breaker: CircuitBreaker) -> None:
    """Test recording token usage that remains well within the budget."""
    circuit_breaker.record_usage(200)
    assert circuit_breaker.current_usage == 200
    assert not circuit_breaker.is_tripped()

    circuit_breaker.record_usage(300)
    assert circuit_breaker.current_usage == 500
    assert not circuit_breaker.is_tripped()


def test_record_usage_exact_limit(circuit_breaker: CircuitBreaker) -> None:
    """Test recording token usage that hits the exact maximum limit."""
    circuit_breaker.record_usage(1000)
    assert circuit_breaker.current_usage == 1000
    assert not circuit_breaker.is_tripped()


def test_record_usage_exceeds_limit(circuit_breaker: CircuitBreaker) -> None:
    """Test that recording usage beyond the limit trips the circuit breaker."""
    circuit_breaker.record_usage(900)
    assert not circuit_breaker.is_tripped()

    with pytest.raises(TokenBudgetExceededError) as exc_info:
        circuit_breaker.record_usage(150)
    
    assert "Token budget exceeded" in str(exc_info.value)
    assert circuit_breaker.is_tripped()
    assert circuit_breaker.current_usage == 1050


def test_check_budget_raises_when_tripped(circuit_breaker: CircuitBreaker) -> None:
    """Test that check_budget raises CircuitBreakerError or TokenBudgetExceededError when tripped."""
    circuit_breaker.record_usage(1000)
    
    with pytest.raises(CircuitBreakerError):
        circuit_breaker.check_budget(1)


def test_check_budget_allows_when_safe(circuit_breaker: CircuitBreaker) -> None:
    """Test that check_budget passes silently when within budget."""
    circuit_breaker.record_usage(500)
    try:
        circuit_breaker.check_budget(499)
    except CircuitBreakerError:
        pytest.fail("check_budget raised CircuitBreakerError unexpectedly.")


def test_reset_circuit_breaker(circuit_breaker: CircuitBreaker) -> None:
    """Test manually resetting the circuit breaker restores normal operation."""
    try:
        circuit_breaker.record_usage(1050)
    except TokenBudgetExceededError:
        pass
    assert circuit_breaker.is_tripped()

    circuit_breaker.reset()
    assert circuit_breaker.current_usage == 0
    assert not circuit_breaker.is_tripped()

    # Should allow usage again after reset
    circuit_breaker.record_usage(500)
    assert circuit_breaker.current_usage == 500


def test_sliding_window_expiration(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test that token usage records expire outside the time window."""
    current_time = 1000.0
    monkeypatch.setattr("time.time", lambda: current_time)

    cb = CircuitBreaker(max_tokens=100, window_seconds=10)

    # Use 80 tokens at t=1000
    cb.record_usage(80)
    assert cb.current_usage == 80
    assert not cb.is_tripped()

    # Advance time by 5 seconds (still within window)
    current_time = 1005.0
    try:
        cb.record_usage(30)
    except TokenBudgetExceededError:
        pass
    # Total usage within window should now be 110, tripping the breaker
    assert cb.is_tripped()

    # Reset for expiration test
    cb.reset()
    current_time = 1000.0
    cb.record_usage(80)
    assert cb.current_usage == 80

    # Advance time past the 10-second window (t = 1011.0)
    current_time = 1011.0
    # Old usage should be purged, current usage should drop to 0
    assert cb.current_usage == 0
    assert not cb.is_tripped()

    # Should be able to record new tokens without error
    cb.record_usage(50)
    assert cb.current_usage == 50
    assert not cb.is_tripped()


def test_partial_window_expiration(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test that only expired entries are pruned from the sliding window."""
    current_time = 1000.0
    monkeypatch.setattr("time.time", lambda: current_time)

    cb = CircuitBreaker(max_tokens=200, window_seconds=10)

    # At t=1000, use 50 tokens
    cb.record_usage(50)

    # At t=1005, use 60 tokens
    current_time = 1005.0
    cb.record_usage(60)
    assert cb.current_usage == 110

    # At t=1012 (first entry at 1000 has expired, second entry at 1005 is still valid)
    current_time = 1012.0
    assert cb.current_usage == 60
    assert not cb.is_tripped()

    # Adding 100 tokens should succeed (60 + 100 = 160 <= 200)
    cb.record_usage(100)
    assert cb.current_usage == 160
    assert not cb.is_tripped()


def test_negative_token_usage_raises_ValueError(circuit_breaker: CircuitBreaker) -> None:
    """Test that recording negative token usage raises a ValueError."""
    with pytest.raises(ValueError):
        circuit_breaker.record_usage(-50)


def test_zero_token_usage(circuit_breaker: CircuitBreaker) -> None:
    """Test recording zero tokens."""
    circuit_breaker.record_usage(0)
    assert circuit_breaker.current_usage == 0
    assert not circuit_breaker.is_tripped()


def test_multiple_small_requests_until_exhaustion(circuit_breaker: CircuitBreaker) -> None:
    """Test exhausting the token budget via many small requests."""
    cb = CircuitBreaker(max_tokens=10, window_seconds=60)
    for _ in range(10):
        cb.record_usage(1)
    
    assert cb.current_usage == 10
    assert not cb.is_tripped()

    with pytest.raises(TokenBudgetExceededError):
        cb.record_usage(1)
    assert cb.is_tripped()


def test_circuit_breaker_error_inheritance() -> None:
    """Verify that TokenBudgetExceededError inherits from CircuitBreakerError."""
    assert issubclass(TokenBudgetExceededError, CircuitBreakerError)
    assert issubclass(CircuitBreakerError, Exception)


def test_get_remaining_budget(circuit_breaker: CircuitBreaker) -> None:
    """Test calculation of remaining budget."""
    assert circuit_breaker.get_remaining_budget() == 1000
    circuit_breaker.record_usage(350)
    assert circuit_breaker.get_remaining_budget() == 650
    circuit_breaker.record_usage(650)
    assert circuit_breaker.get_remaining_budget() == 0


def test_remaining_budget_cannot_be_negative(circuit_breaker: CircuitBreaker) -> None:
    """Test that remaining budget floors at zero even if over-allocated via force."""
    circuit_breaker._current_usage = 1200  # Internal override for testing edge case
    assert circuit_breaker.get_remaining_budget() == 0


def test_concurrent_usage_tracking_simulation(circuit_breaker: CircuitBreaker) -> None:
    """Simulate rapid sequential high-volume requests."""
    for _ in range(10):
        circuit_breaker.record_usage(100)
    
    assert circuit_breaker.current_usage == 1000
    assert not circuit_breaker.is_tripped()

    with pytest.raises(TokenBudgetExceededError):
        circuit_breaker.record_usage(1)


def test_window_seconds_validation() -> None:
    """Test that initializing with invalid window or max tokens raises ValueError."""
    with pytest.raises(ValueError):
        CircuitBreaker(max_tokens=0, window_seconds=60)

    with pytest.raises(ValueError):
        CircuitBreaker(max_tokens=-100, window_seconds=60)

    with pytest.raises(ValueError):
        CircuitBreaker(max_tokens=1000, window_seconds=0)

    with pytest.raises(ValueError):
        CircuitBreaker(max_tokens=1000, window_seconds=-10)


def test_audit_callback_integration(circuit_breaker: CircuitBreaker) -> None:
    """Test that an optional audit callback is triggered when the circuit trips."""
    mock_callback = MagicMock()
    circuit_breaker.set_trip_callback(mock_callback)

    circuit_breaker.record_usage(1000)
    mock_callback.assert_not_called()

    with pytest.raises(TokenBudgetExceededError):
        circuit_breaker.record_usage(1)

    mock_callback.assert_called_once()


def test_trip_callback_only_fires_once_per_trip(circuit_breaker: CircuitBreaker) -> None:
    """Test that the trip callback fires exactly once when transitioning from safe to tripped."""
    mock_callback = MagicMock()
    circuit_breaker.set_trip_callback(mock_callback)

    with pytest.raises(TokenBudgetExceededError):
        circuit_breaker.record_usage(1050)

    with pytest.raises(CircuitBreakerError):
        circuit_breaker.record_usage(50)

    mock_callback.assert_called_once()


def test_callback_reset_behavior(circuit_breaker: CircuitBreaker) -> None:
    """Test that resetting allows the trip callback to fire again on subsequent trips."""
    mock_callback = MagicMock()
    circuit_breaker.set_trip_callback(mock_callback)

    with pytest.raises(TokenBudgetExceededError):
        circuit_breaker.record_usage(1500)
    assert mock_callback.call_count == 1

    circuit_breaker.reset()
    assert not circuit_breaker.is_tripped()

    with pytest.raises(TokenBudgetExceededError):
        circuit_breaker.record_usage(1500)
    assert mock_callback.call_count == 2
