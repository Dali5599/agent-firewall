import json
import logging
import time
from typing import AsyncGenerator, Dict, Any, Optional

import httpx
from fastapi import APIRouter, Request, Response, HTTPException, status
from fastapi.responses import StreamingResponse

from agent_firewall.config import get_settings
from agent_firewall.db.database import get_db
from agent_firewall.db.repository import AuditRepository
from agent_firewall.security.redaction import redact_content
from agent_firewall.security.circuit_breaker import check_token_budget, record_token_usage
from agent_firewall.security.command_blocker import detect_destructive_command

logger = logging.getLogger("agent_firewall.proxy.router")
router = APIRouter(prefix="/v1", tags=["proxy"])

HTTP_CLIENT = httpx.AsyncClient(timeout=60.0)


async def _stream_proxy_response(
    resp_stream: httpx.Response,
    audit_id: int,
    endpoint: str,
    target_url: str,
    request_payload: Dict[str, Any],
) -> AsyncGenerator[bytes, None]:
    """
    Proxies the response stream from upstream, performing real-time SSE parsing,
    redaction, token accumulation, and final audit logging.
    """
    accumulated_content = ""
    prompt_tokens = request_payload.get("estimated_prompt_tokens", 50)
    completion_tokens = 0
    start_time = time.time()

    try:
        async for chunk in resp_stream.aiter_bytes():
            yield chunk
            # Basic SSE text decoding for accumulation and audit
            chunk_str = chunk.decode("utf-8", errors="ignore")
            for line in chunk_str.splitlines():
                if line.startswith("data: ") and line != "data: [DONE]":
                    try:
                        data = json.loads(line[6:])
                        choices = data.get("choices", [])
                        if choices:
                            delta = choices[0].get("delta", {})
                            content = delta.get("content")
                            if content:
                                accumulated_content += content
                                completion_tokens += max(1, len(content) // 4)
                        # Anthropic messages SSE format support
                        elif data.get("type") == "content_block_delta":
                            delta = data.get("delta", {})
                            content = delta.get("text")
                            if content:
                                accumulated_content += content
                                completion_tokens += max(1, len(content) // 4)
                    except json.JSONDecodeError:
                        continue
    except Exception as e:
        logger.error(f"Error streaming response from upstream: {e}")
        raise
    finally:
        latency_ms = int((time.time() - start_time) * 1000)
        redacted_response = redact_content(accumulated_content)
        total_tokens = prompt_tokens + completion_tokens

        try:
            with get_db() as db:
                repo = AuditRepository(db)
                repo.complete_audit_log(
                    audit_id=audit_id,
                    status_code=resp_stream.status_code,
                    response_payload={"streamed": True, "content": redacted_response},
                    tokens_used=total_tokens,
                    latency_ms=latency_ms,
                    blocked=False,
                )
            record_token_usage(total_tokens)
        except Exception as db_err:
            logger.error(f"Failed to finalize audit log in stream: {db_err}")


@router.post("/chat/completions")
async def proxy_chat_completions(request: Request) -> Response:
    """
    Transparent reverse proxy for OpenAI /v1/chat/completions endpoints.
    Applies redaction, command blocking, token circuit breaking, and SQLite audit logging.
    """
    settings = get_settings()
    start_time = time.time()

    try:
        body = await request.json()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid JSON payload: {str(e)}"
        )

    # 1. Security Inspections & Redactions
    messages = body.get("messages", [])
    for msg in messages:
        content = msg.get("content", "")
        if isinstance(content, str):
            # Check for destructive bash commands if applicable
            if detect_destructive_command(content):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Agent Firewall Blocked: Destructive system command detected."
                )
            # Redact secrets
            msg["content"] = redact_content(content)

    # 2. Circuit Breaker Token Budget Check
    estimated_prompt_tokens = sum(len(str(m.get("content", ""))) // 4 for m in messages)
    body["estimated_prompt_tokens"] = estimated_prompt_tokens

    if not check_token_budget(estimated_prompt_tokens):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Agent Firewall Circuit Breaker: Hard token budget exceeded."
        )

    # 3. Create Initial Audit Log
    client_ip = request.client.host if request.client else "unknown"
    try:
        with get_db() as db:
            repo = AuditRepository(db)
            audit_id = repo.create_audit_log(
                endpoint="/v1/chat/completions",
                method="POST",
                request_payload=body,
                client_ip=client_ip
            )
    except Exception as e:
        logger.error(f"Failed to create audit log: {e}")
        audit_id = 0

    # 4. Forward Request to Upstream OpenAI Provider
    upstream_url = f"{settings.openai_api_base}/chat/completions"
    headers = dict(request.headers)
    headers.pop("host", None)
    headers.pop("content-length", None)
    
    if settings.openai_api_key and "authorization" not in {k.lower() for k in headers}:
        headers["Authorization"] = f"Bearer {settings.openai_api_key}"

    is_streaming = body.get("stream", False)

    try:
        if is_streaming:
            req = HTTP_CLIENT.build_request("POST", upstream_url, json=body, headers=headers)
            resp = await HTTP_CLIENT.send(req, stream=True)
            return StreamingResponse(
                _stream_proxy_response(resp, audit_id, "/v1/chat/completions", upstream_url, body),
                status_code=resp.status_code,
                media_type="text/event-stream"
            )
        else:
            resp = await HTTP_CLIENT.post(upstream_url, json=body, headers=headers)
            latency_ms = int((time.time() - start_time) * 1000)
            
            resp_data = {}
            try:
                resp_data = resp.json()
            except Exception:
                resp_data = {"raw_text": resp.text}

            # Redact response content
            if "choices" in resp_data:
                for choice in resp_data["choices"]:
                    msg = choice.get("message", {})
                    if "content" in msg and isinstance(msg["content"], str):
                        msg["content"] = redact_content(msg["content"])

            usage = resp_data.get("usage", {})
            total_tokens = usage.get("total_tokens", estimated_prompt_tokens + 50)

            # Finalize audit log
            try:
                with get_db() as db:
                    repo = AuditRepository(db)
                    repo.complete_audit_log(
                        audit_id=audit_id,
                        status_code=resp.status_code,
                        response_payload=resp_data,
                        tokens_used=total_tokens,
                        latency_ms=latency_ms,
                        blocked=False
                    )
                record_token_usage(total_tokens)
            except Exception as e:
                logger.error(f"Failed to finalize audit log: {e}")

            return Response(
                content=json.dumps(resp_data),
                status_code=resp.status_code,
                media_type="application/json"
            )

    except httpx.RequestError as exc:
        latency_ms = int((time.time() - start_time) * 1000)
        error_msg = f"Upstream connection error: {str(exc)}"
        logger.error(error_msg)
        try:
            with get_db() as db:
                repo = AuditRepository(db)
                repo.complete_audit_log(
                    audit_id=audit_id,
                    status_code=502,
                    response_payload={"error": error_msg},
                    tokens_used=estimated_prompt_tokens,
                    latency_ms=latency_ms,
                    blocked=True
                )
        except Exception:
            pass
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=error_msg)


@router.post("/messages")
async def proxy_anthropic_messages(request: Request) -> Response:
    """
    Transparent reverse proxy for Anthropic /v1/messages endpoints.
    Applies redaction, command blocking, token circuit breaking, and SQLite audit logging.
    """
    settings = get_settings()
    start_time = time.time()

    try:
        body = await request.json()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid JSON payload: {str(e)}"
        )

    # 1. Security Inspections & Redactions
    messages = body.get("messages", [])
    for msg in messages:
        content = msg.get("content", "")
        if isinstance(content, str):
            if detect_destructive_command(content):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Agent Firewall Blocked: Destructive system command detected in Anthropic payload."
                )
            msg["content"] = redact_content(content)
        elif isinstance(content, list):
            for block in content:
                if isinstance(block, dict) and "text" in block:
                    txt = block["text"]
                    if detect_destructive_command(txt):
                        raise HTTPException(
                            status_code=status.HTTP_403_FORBIDDEN,
                            detail="Agent Firewall Blocked: Destructive system command detected in content block."
                        )
                    block["text"] = redact_content(txt)

    estimated_prompt_tokens = sum(len(str(m.get("content", ""))) // 4 for m in messages)
    body["estimated_prompt_tokens"] = estimated_prompt_tokens

    if not check_token_budget(estimated_prompt_tokens):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Agent Firewall Circuit Breaker: Hard token budget exceeded."
        )

    client_ip = request.client.host if request.client else "unknown"
    try:
        with get_db() as db:
            repo = AuditRepository(db)
            audit_id = repo.create_audit_log(
                endpoint="/v1/messages",
                method="POST",
                request_payload=body,
                client_ip=client_ip
            )
    except Exception as e:
        logger.error(f"Failed to create audit log for Anthropic: {e}")
        audit_id = 0

    upstream_url = f"{settings.anthropic_api_base}/messages"
    headers = dict(request.headers)
    headers.pop("host", None)
    headers.pop("content-length", None)

    if settings.anthropic_api_key and "x-api-key" not in {k.lower() for k in headers}:
        headers["x-api-key"] = settings.anthropic_api_key

    if "anthropic-version" not in {k.lower() for k in headers}:
        headers["anthropic-version"] = "2023-06-01"

    is_streaming = body.get("stream", False)

    try:
        if is_streaming:
            req = HTTP_CLIENT.build_request("POST", upstream_url, json=body, headers=headers)
            resp = await HTTP_CLIENT.send(req, stream=True)
            return StreamingResponse(
                _stream_proxy_response(resp, audit_id, "/v1/messages", upstream_url, body),
                status_code=resp.status_code,
                media_type="text/event-stream"
            )
        else:
            resp = await HTTP_CLIENT.post(upstream_url, json=body, headers=headers)
            latency_ms = int((time.time() - start_time) * 1000)

            resp_data = {}
            try:
                resp_data = resp.json()
            except Exception:
                resp_data = {"raw_text": resp.text}

            content_blocks = resp_data.get("content", [])
            for block in content_blocks:
                if isinstance(block, dict) and "text" in block:
                    block["text"] = redact_content(block["text"])

            usage = resp_data.get("usage", {})
            total_tokens = usage.get("input_tokens", 0) + usage.get("output_tokens", 50)
            if total_tokens == 0:
                total_tokens = estimated_prompt_tokens + 50

            try:
                with get_db() as db:
                    repo = AuditRepository(db)
                    repo.complete_audit_log(
                        audit_id=audit_id,
                        status_code=resp.status_code,
                        response_payload=resp_data,
                        tokens_used=total_tokens,
                        latency_ms=latency_ms,
                        blocked=False
                    )
                record_token_usage(total_tokens)
            except Exception as e:
                logger.error(f"Failed to finalize Anthropic audit log: {e}")

            return Response(
                content=json.dumps(resp_data),
                status_code=resp.status_code,
                media_type="application/json"
            )

    except httpx.RequestError as exc:
        latency_ms = int((time.time() - start_time) * 1000)
        error_msg = f"Anthropic upstream connection error: {str(exc)}"
        logger.error(error_msg)
        try:
            with get_db() as db:
                repo = AuditRepository(db)
                repo.complete_audit_log(
                    audit_id=audit_id,
                    status_code=502,
                    response_payload={"error": error_msg},
                    tokens_used=estimated_prompt_tokens,
                    latency_ms=latency_ms,
                    blocked=True
                )
        except Exception:
            pass
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=error_msg)
