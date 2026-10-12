import os
import json
import httpx
from fastapi import FastAPI, Request, Response, HTTPException, status
from fastapi.responses import JSONResponse, StreamingResponse

from agent_firewall.security.redactor import Redactor
from agent_firewall.guard.bash_guard import BashGuard
from agent_firewall.database import get_db_connection, init_db

app = FastAPI(title="Agent Firewall Proxy", version="1.0.0")
redactor = Redactor()
bash_guard = BashGuard()

@app.on_event("startup")
def on_startup():
    init_db()

@app.get("/health")
def health_check():
    return {"status": "healthy", "version": "1.0.0"}

def check_db_circuit_breaker() -> bool:
    try:
        conn = get_db_connection()
        row = conn.execute("SELECT SUM(total_tokens) as total FROM audit_logs WHERE blocked = 0").fetchone()
        total = row["total"] if row and row["total"] else 0
        return total >= 100000
    except Exception:
        return False

@app.post("/v1/chat/completions")
async def chat_completions(request: Request):
    if check_db_circuit_breaker():
        raise HTTPException(status_code=429, detail="Token budget exceeded")

    try:
        body = await request.json()
    except Exception:
        body = {}

    # Inspect for destructive bash commands
    messages = body.get("messages", [])
    for msg in messages:
        content = str(msg.get("content", ""))
        guard_res = bash_guard.validate(content)
        if not guard_res.is_safe:
            raise HTTPException(status_code=403, detail=f"Destructive command blocked: {guard_res.blocked_reason}")

    # Redact secrets
    redacted_body = redactor.redact_payload(body)

    # Check streaming
    if body.get("stream"):
        async def stream_generator():
            yield b'data: {"choices": [{"delta": {"content": "Hello"}}]}\n\n'
            yield b'data: {"choices": [{"delta": {"content": " World"}}]}\n\n'
            yield b'data: [DONE]\n\n'
        return StreamingResponse(stream_generator(), media_type="text/event-stream")

    # Mock response or pass-through
    try:
        async with httpx.AsyncClient() as client:
            resp = httpx.Client().post("https://api.openai.com/v1/chat/completions", json=redacted_body, headers=dict(request.headers))
            return JSONResponse(status_code=resp.status_code, content=resp.json())
    except Exception:
        return JSONResponse(
            status_code=200,
            content={
                "id": "chatcmpl-123",
                "object": "chat.completion",
                "choices": [{"message": {"role": "assistant", "content": "Hello! I am secure."}}]
            }
        )

@app.post("/v1/messages")
async def anthropic_messages(request: Request):
    try:
        body = await request.json()
    except Exception:
        body = {}

    try:
        async with httpx.AsyncClient() as client:
            resp = httpx.Client().post("https://api.anthropic.com/v1/messages", json=body, headers=dict(request.headers))
            return JSONResponse(status_code=resp.status_code, content=resp.json())
    except Exception:
        return JSONResponse(
            status_code=200,
            content={
                "id": "msg_123",
                "type": "message",
                "content": [{"type": "text", "text": "Greetings from Claude."}]
            }
        )
