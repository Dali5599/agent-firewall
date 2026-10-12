import json
import time
import logging
from typing import AsyncGenerator, Dict, Any, Tuple
from fastapi import Request, Response
from fastapi.responses import StreamingResponse
import httpx

from agent_firewall.redactor.engine import RedactorEngine
from agent_firewall.guard.engine import GuardEngine
from agent_firewall.budget.circuit_breaker import BudgetCircuitBreaker
from agent_firewall.audit.logger import AuditLogger

logger = logging.getLogger("agent_firewall.proxy.middleware")


class ProxyMiddleware:
    """
    Asynchronous proxy middleware intercepting requests and responses for AI agents.
    Integrates redactor, guardrails, budget control, and sovereign audit logging.
    Maintains sub-2ms overhead and supports both standard JSON payloads and Server-Sent Events (SSE) streaming.
    """

    def __init__(
        self,
        redactor: RedactorEngine,
        guard: GuardEngine,
        budget: BudgetCircuitBreaker,
        audit_logger: AuditLogger,
        upstream_client: httpx.AsyncClient,
    ) -> None:
        self.redactor = redactor
        self.guard = guard
        self.budget = budget
        self.audit = audit_logger
        self.client = upstream_client

    async def __call__(self, request: Request, call_next) -> Response:
        """
        Intercepts incoming HTTP requests, applies security layers, forwards to upstream,
        and intercepts outbound responses (including streaming SSE).
        """
        start_time = time.perf_counter()
        agent_id = request.headers.get("X-Agent-ID", "default-agent")
        path = request.url.path
        method = request.method

        # 1. Budget Pre-check
        if not await self.budget.check_allowance(agent_id):
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            await self.audit.log_event(
                agent_id=agent_id,
                endpoint=path,
                event_type="BUDGET_EXCEEDED",
                status="BLOCKED",
                latency_ms=elapsed_ms,
                details={"reason": "Hard token budget circuit breaker tripped."},
            )
            return Response(
                content=json.dumps({"error": {"message": "Agent Firewall: Budget circuit breaker tripped. Limit reached.", "type": "budget_exceeded"}}),
                status_code=429,
                media_type="application/json"
            )

        # 2. Read and parse request body
        try:
            body_bytes = await request.body()
            body_json = json.loads(body_bytes) if body_bytes else {}
        except Exception as e:
            logger.error(f"Failed to parse incoming request JSON: {e}")
            body_json = {}

        # 3. Redact incoming request payload
        redacted_body, redaction_count = self.redactor.redact_payload(body_json)

        # 4. Guardrail validation on incoming prompt/messages
        messages = body_json.get("messages", [])
        is_safe, guard_violation = self.guard.inspect_messages(messages)
        if not is_safe:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            await self.audit.log_event(
                agent_id=agent_id,
                endpoint=path,
                event_type="GUARD_VIOLATION",
                status="BLOCKED",
                latency_ms=elapsed_ms,
                details={"violation": guard_violation},
            )
            return Response(
                content=json.dumps({"error": {"message": f"Agent Firewall Guardrail Triggered: {guard_violation}", "type": "guard_violation"}}),
                status_code=403,
                media_type="application/json"
            )

        # 5. Prepare upstream request headers and URL
        upstream_headers = dict(request.headers)
        upstream_headers.pop("host", None)
        upstream_headers.pop("content-length", None)

        target_url = str(request.url)
        # Assuming upstream routing based on configuration or headers
        # For simplicity, proxy directly to target path maintaining host if configured
        
        is_streaming = body_json.get("stream", False)

        try:
            if is_streaming:
                return await self._handle_streaming_response(
                    method=method,
                    url=target_url,
                    headers=upstream_headers,
                    json_data=redacted_body,
                    agent_id=agent_id,
                    path=path,
                    start_time=start_time,
                    redaction_count=redaction_count
                )
            else:
                return await self._handle_standard_response(
                    method=method,
                    url=target_url,
                    headers=upstream_headers,
                    json_data=redacted_body,
                    agent_id=agent_id,
                    path=path,
                    start_time=start_time,
                    redaction_count=redaction_count
                )
        except httpx.HTTPError as exc:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            logger.error(f"Upstream HTTP error: {exc}")
            await self.audit.log_event(
                agent_id=agent_id,
                endpoint=path,
                event_type="UPSTREAM_ERROR",
                status="ERROR",
                latency_ms=elapsed_ms,
                details={"error": str(exc)},
            )
            return Response(
                content=json.dumps({"error": {"message": "Agent Firewall: Upstream service unreachable.", "type": "upstream_error"}}),
                status_code=502,
                media_type="application/json"
            )

    async def _handle_standard_response(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
        json_data: Dict[str, Any],
        agent_id: str,
        path: str,
        start_time: float,
        redaction_count: int
    ) -> Response:
        upstream_response = await self.client.request(
            method=method,
            url=url,
            headers=headers,
            json=json_data,
        )

        response_body = upstream_response.content
        try:
            response_json = upstream_response.json()
            # Redact outgoing response
            redacted_resp, out_redactions = self.redactor.redact_payload(response_json)
            final_content = json.dumps(redacted_resp)
            
            # Extract token usage for budget tracking
            usage = response_json.get("usage", {})
            total_tokens = usage.get("total_tokens", 0)
            if total_tokens > 0:
                await self.budget.consume_tokens(agent_id, total_tokens)

        except Exception:
            final_content = response_body
            total_tokens = 0

        elapsed_ms = (time.perf_counter() - start_time) * 1000

        await self.audit.log_event(
            agent_id=agent_id,
            endpoint=path,
            event_type="API_CALL",
            status="SUCCESS" if upstream_response.status_code < 400 else "UPSTREAM_FAIL",
            latency_ms=elapsed_ms,
            tokens_used=total_tokens,
            redactions_count=redaction_count,
            details={"status_code": upstream_response.status_code}
        )

        return Response(
            content=final_content,
            status_code=upstream_response.status_code,
            headers=dict(upstream_response.headers),
            media_type=upstream_response.headers.get("content-type", "application/json")
        )

    async def _handle_streaming_response(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
        json_data: Dict[str, Any],
        agent_id: str,
        path: str,
        start_time: float,
        redaction_count: int
    ) -> StreamingResponse:
        
        req = self.client.build_request(method, url, headers=headers, json=json_data)
        upstream_response = await self.client.send(req, stream=True)

        async def stream_generator() -> AsyncGenerator[bytes, None]:
            accumulated_tokens = 0
            try:
                async for chunk in upstream_response.aiter_bytes():
                    # Parse SSE lines if applicable
                    try:
                        chunk_str = chunk.decode("utf-8")
                        lines = chunk_str.split("\n")
                        processed_lines = []
                        for line in lines:
                            if line.startswith("data: ") and line != "data: [DONE]":
                                json_str = line[6:]
                                data_obj = json.loads(json_str)
                                redacted_data, _ = self.redactor.redact_payload(data_obj)
                                
                                # Estimate token usage from chunk if available
                                usage = data_obj.get("usage")
                                if usage and isinstance(usage, dict):
                                    accumulated_tokens = usage.get("total_tokens", accumulated_tokens)

                                processed_lines.append(f"data: {json.dumps(redacted_data)}")
                            else:
                    
                                processed_lines.append(line)
                        yield ("\n".join(processed_lines)).encode("utf-8")
                    except Exception:
                        yield chunk
            finally:
                await upstream_response.aclose()
                elapsed_ms = (time.perf_counter() - start_time) * 1000
                if accumulated_tokens > 0:
                    await self.budget.consume_tokens(agent_id, accumulated_tokens)

                await self.audit.log_event(
                    agent_id=agent_id,
                    endpoint=path,
                    event_type="STREAM_API_CALL",
                    status="SUCCESS",
                    latency_ms=elapsed_ms,
                    tokens_used=accumulated_tokens,
                    redactions_count=redaction_count,
                    details={"streaming": True}
                )

        return StreamingResponse(
            stream_generator(),
            status_code=upstream_response.status_code,
            headers=dict(upstream_response.headers),
            media_type="text/event-stream"
        )
