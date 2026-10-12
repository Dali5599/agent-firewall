import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
import json
import os

from agent_firewall.proxy import app
from agent_firewall.database import init_db, get_db_connection

@pytest.fixture(autouse=True)
def setup_test_db():
    os.environ["DATABASE_URL"] = ":memory:"
    init_db()
    yield

@pytest.fixture
def client():
    return TestClient(app)

def test_health_check(client: TestClient):
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "version" in data

def test_proxy_openai_chat_completion_allowed(client: TestClient):
    payload = {
        "model": "gpt-4",
        "messages": [{"role": "user", "content": "Hello, how are you?"}]
    }
    
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "id": "chatcmpl-123",
        "object": "chat.completion",
        "choices": [{"message": {"role": "assistant", "content": "Hello! I am secure."}}]
    }
    mock_response.headers = {"content-type": "application/json"}
    
    with patch("httpx.Client.post", return_value=mock_response) as mock_post:
        response = client.post(
            "/v1/chat/completions",
            json=payload,
            headers={"Authorization": "Bearer test-token"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["choices"][0]["message"]["content"] == "Hello! I am secure."
        mock_post.assert_called_once()

def test_proxy_anthropic_messages_allowed(client: TestClient):
    payload = {
        "model": "claude-3-opus-20240229",
        "messages": [{"role": "user", "content": "Hello Claude"}]
    }
    
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "id": "msg_123",
        "type": "message",
        "content": [{"type": "text", "text": "Greetings from Claude."}]
    }
    mock_response.headers = {"content-type": "application/json"}
    
    with patch("httpx.Client.post", return_value=mock_response) as mock_post:
        response = client.post(
            "/v1/messages",
            json=payload,
            headers={"x-api-key": "test-anthropic-key", "anthropic-version": "2023-06-01"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["content"][0]["text"] == "Greetings from Claude."
        mock_post.assert_called_once()

def test_proxy_secret_redaction_in_request(client: TestClient):
    payload = {
        "model": "gpt-4",
        "messages": [{"role": "user", "content": "My secret API key is sk-1234567890abcdef1234567890abcdef"}]
    }
    
    captured_request = None
    
    def side_effect(url, **kwargs):
        nonlocal captured_request
        captured_request = kwargs.get("json")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"choices": [{"message": {"role": "assistant", "content": "Acknowledged."}}]}
        mock_resp.headers = {"content-type": "application/json"}
        return mock_resp

    with patch("httpx.Client.post", side_effect=side_effect):
        response = client.post(
            "/v1/chat/completions",
            json=payload,
            headers={"Authorization": "Bearer test-token"}
        )
        assert response.status_code == 200
        assert "[REDACTED_SECRET]" in captured_request["messages"][0]["content"]
        assert "sk-1234567890abcdef" not in captured_request["messages"][0]["content"]

def test_proxy_destructive_command_blocking(client: TestClient):
    payload = {
        "model": "gpt-4",
        "messages": [{"role": "user", "content": "Run this command: rm -rf /"}]
    }
    
    response = client.post(
        "/v1/chat/completions",
        json=payload,
        headers={"Authorization": "Bearer test-token"}
    )
    
    assert response.status_code == 403
    data = response.json()
    assert "Destructive command blocked" in data["detail"]

def test_proxy_token_budget_circuit_breaker(client: TestClient):
    conn = get_db_connection()
    conn.execute(
        "INSERT INTO audit_logs (timestamp, endpoint, model, prompt_tokens, completion_tokens, total_tokens, status_code, blocked) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        ("2026-01-01 00:00:00", "/v1/chat/completions", "gpt-4", 50000, 50000, 100000, 200, 0)
    )
    conn.commit()
    conn.close()

    payload = {
        "model": "gpt-4",
        "messages": [{"role": "user", "content": "Another massive prompt"}]
    }

    response = client.post(
        "/v1/chat/completions",
        json=payload,
        headers={"Authorization": "Bearer test-token"}
    )

    assert response.status_code == 429
    data = response.json()
    assert "Token budget exceeded" in data["detail"]

def test_proxy_streaming_response(client: TestClient):
    payload = {
        "model": "gpt-4",
        "stream": True,
        "messages": [{"role": "user", "content": "Stream data to me"}]
    }
    
    streaming_chunks = [
        b'data: {"choices": [{"delta": {"content": "Hello"}}]}\n\n',
        b'data: {"choices": [{"delta": {"content": " World"}}]}\n\n',
        b'data: [DONE]\n\n'
    ]

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.iter_bytes.return_value = streaming_chunks
    mock_response.headers = {"content-type": "text/event-stream"}

    with patch("httpx.Client.stream") as mock_stream:
        mock_context = MagicMock()
        mock_context.__enter__.return_value = mock_response
        mock_stream.return_value = mock_context

        response = client.post(
            "/v1/chat/completions",
            json=payload,
            headers={"Authorization": "Bearer test-token"}
        )

        assert response.status_code == 200
        assert "text/event-stream" in response.headers["content-type"]
        body = response.text
        assert "Hello" in body
        assert "World" in body
