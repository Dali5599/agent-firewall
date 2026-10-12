import pytest
from app.redactor import Redactor

@pytest.fixture
def redactor() -> Redactor:
    """Fixture providing a default Redactor instance."""
    return Redactor()

def test_redactor_initialization(redactor: Redactor) -> None:
    """Test that the Redactor initializes correctly with default patterns."""
    assert redactor is not None
    assert len(redactor.compiled_patterns) > 0

def test_redactor_openai_api_key(redactor: Redactor) -> None:
    """Test detection and redaction of OpenAI API keys."""
    text = "My secret OpenAI key is sk-proj-123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012345."
    redacted = redactor.redact(text)
    assert "sk-proj-123456789" not in redacted
    assert "[REDACTED_SECRET]" in redacted

def test_redactor_anthropic_api_key(redactor: Redactor) -> None:
    """Test detection and redaction of Anthropic API keys."""
    text = "Here is the anthropic token: sk-ant-api03-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789."
    redacted = redactor.redact(text)
    assert "sk-ant-api03-" not in redacted
    assert "[REDACTED_SECRET]" in redacted

def test_redactor_aws_access_key(redactor: Redactor) -> None:
    """Test detection and redaction of AWS Access Key IDs."""
    text = "AWS credentials AKIAIOSFODNN7EXAMPLE are embedded here."
    redacted = redactor.redact(text)
    assert "AKIAIOSFODNN7EXAMPLE" not in redacted
    assert "[REDACTED_SECRET]" in redacted

def test_redactor_github_token(redactor: Redactor) -> None:
    """Test detection and redaction of GitHub Personal Access Tokens."""
    text = "Use ghp_1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP for authentication."
    redacted = redactor.redact(text)
    assert "ghp_1234567890" not in redacted
    assert "[REDACTED_SECRET]" in redacted

def test_redactor_jwt_token(redactor: Redactor) -> None:
    """Test detection and redaction of JSON Web Tokens."""
    jwt_sample = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    text = f"Bearer token is {jwt_sample}."
    redacted = redactor.redact(text)
    assert jwt_sample not in redacted
    assert "[REDACTED_SECRET]" in redacted

def test_redactor_private_key(redactor: Redactor) -> None:
    """Test detection and redaction of PEM private keys."""
    pem_text = """-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC3
-----END PRIVATE KEY-----"""
    text = f"Keep this safe:\n{pem_text}\nEnd of key."
    redacted = redactor.redact(text)
    assert "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC3" not in redacted
    assert "[REDACTED_SECRET]" in redacted

def test_redactor_slack_token(redactor: Redactor) -> None:
    """Test detection and redaction of Slack tokens."""
    text = "Slack bot token xoxb-123456789012-1234567890123-abcdef123456."
    redacted = redactor.redact(text)
    assert "xoxb-123456789012" not in redacted
    assert "[REDACTED_SECRET]" in redacted

def test_redactor_stripe_key(redactor: Redactor) -> None:
    """Test detection and redaction of Stripe secret keys."""
    text = "Stripe secret key sk_test_1234567890abcdefghijklmnopqrstuvwxyz."
    redacted = redactor.redact(text)
    assert "sk_test_1234567890" not in redacted
    assert "[REDACTED_SECRET]" in redacted

def test_redactor_google_api_key(redactor: Redactor) -> None:
    """Test detection and redaction of Google API keys."""
    text = "Google AI key AIzaSyA-1234567890abcdefghijklmnopqrstuvwx."
    redacted = redactor.redact(text)
    assert "AIzaSyA-1234567890" not in redacted
    assert "[REDACTED_SECRET]" in redacted

def test_redactor_no_secrets(redactor: Redactor) -> None:
    """Test that clean text without secrets remains completely untouched."""
    text = "Hello world! This is a completely normal message about cooking recipes and python programming."
    redacted = redactor.redact(text)
    assert redacted == text

def test_redactor_multiple_secrets(redactor: Redactor) -> None:
    """Test redaction of multiple secrets within the same string."""
    text = "OpenAI: sk-proj-123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012345 and GitHub: ghp_1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP."
    redacted = redactor.redact(text)
    assert "sk-proj-123456789" not in redacted
    assert "ghp_1234567890" not in redacted
    assert redacted.count("[REDACTED_SECRET]") == 2

def test_redactor_dict_payload(redactor: Redactor) -> None:
    """Test recursive redaction across nested dictionaries and lists (JSON payload simulation)."""
    payload = {
        "model": "gpt-4",
        "messages": [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "My API key is sk-proj-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890123."}
        ],
        "metadata": {
            "token": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ab",
            "safe_field": "no secrets here"
        }
    }
    redacted_payload = redactor.redact_payload(payload)
    
    assert redacted_payload["model"] == "gpt-4"
    assert redacted_payload["messages"][0]["content"] == "You are a helpful assistant."
    assert "sk-proj-" not in redacted_payload["messages"][1]["content"]
    assert "[REDACTED_SECRET]" in redacted_payload["messages"][1]["content"]
    assert "ghp_" not in redacted_payload["metadata"]["token"]
    assert redacted_payload["metadata"]["safe_field"] == "no secrets here"

def test_redactor_custom_placeholder(redactor: Redactor) -> None:
    """Test redacting with a custom placeholder string."""
    text = "Secret: sk-proj-123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012345."
    redacted = redactor.redact(text, placeholder="[SECRET]")
    assert "[SECRET]" in redacted
    assert "sk-proj-123456789" not in redacted

def test_redactor_empty_string(redactor: Redactor) -> None:
    """Test handling of empty string input."""
    assert redactor.redact("") == ""

def test_redactor_none_input(redactor: Redactor) -> None:
    """Test handling of None input gracefully."""
    # Assuming the implementation might handle non-string types or raise TypeError;
    # if it handles None or raises, let's verify robust handling.
    with pytest.raises((TypeError, AttributeError)):
        redactor.redact(None)  # type: ignore

def test_redactor_partial_match_false_alarm_avoidance(redactor: Redactor) -> None:
    """Test that standard English text resembling keys loosely doesn't trigger false positives unnecessarily."""
    text = "The word skill and skin are completely normal English words."
    redacted = redactor.redact(text)
    assert redacted == text

def test_redactor_add_custom_pattern(redactor: Redactor) -> None:
    """Test adding a custom regex pattern dynamically to the redactor."""
    redactor.add_pattern(r"SUPER-SECRET-[0-9]+", "[REDACTED_CUSTOM]")
    text = "My classified code is SUPER-SECRET-998877."
    redacted = redactor.redact(text)
    assert "SUPER-SECRET-998877" not in redacted
    assert "[REDACTED_CUSTOM]" in redacted

def test_redactor_check_contains_secrets(redactor: Redactor) -> None:
    """Test the utility method that detects if secrets exist without modifying text."""
    clean_text = "Just a friendly chat about gardening."
    secret_text = "Here is my token: sk-ant-api03-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789."
    
    assert redactor.contains_secrets(clean_text) is False
    assert redactor.contains_secrets(secret_text) is True

def test_redactor_metrics_tracking(redactor: Redactor) -> None:
    """Test that the redactor tracks redaction counts/metrics internally if implemented."""
    text = "Key 1: sk-proj-123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012345 and Key 2: ghp_1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP."
    redactor.redact(text)
    
    if hasattr(redactor, "redaction_count"):
        assert redactor.redaction_count >= 2
