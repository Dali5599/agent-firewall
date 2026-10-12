import logging
from typing import Any, AsyncGenerator, Dict, Optional
import httpx
from fastapi import Request, Response
from fastapi.responses import StreamingResponse

logger = logging.getLogger("agent_firewall.proxy.client")

class UpstreamClient:
    """
    High-performance asynchronous HTTP client for forwarding intercepted
    AI agent traffic to upstream providers (OpenAI, Anthropic, etc.) with
    minimal overhead (<2ms target) and full support for Server-Sent Events (SSE).
    """

    def __init__(self, timeout: float = 60.0, max_connections: int = 100, max_keepalive_connections: int = 20):
        self.timeout = httpx.Timeout(timeout, connect=5.0)
        self.limits = httpx.Limits(
            max_connections=max_connections,
            max_keepalive_connections=max_keepalive_connections
        )
        self._client: Optional[httpx.AsyncClient] = None

    async def initialize(self) -> None:
        """Initializes the underlying httpx AsyncClient with connection pooling."""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=self.timeout,
                limits=self.limits,
                follow_redirects=False,
                http2=True
            )
            logger.info("Upstream HTTPX client initialized with HTTP/2 and connection pooling.")

    async def close(self) -> None:
        """Closes the underlying httpx AsyncClient."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            logger.info("Upstream HTTPX client closed.")

    async def forward_request(
        self,
        request: Request,
        upstream_url: str,
        modified_body: Optional[bytes] = None,
        extra_headers: Optional[Dict[str, str]] = None
    ) -> Response:
        """
        Forwards an incoming client request to the specified upstream URL,
        preserving method, headers, and body (or using a modified body/headers).
        Handles both standard JSON responses and SSE streaming responses transparently.
        """
        if self._client is None or self._client.is_closed:
            await self.initialize()

        # Prepare headers
        headers = dict(request.headers)
        
        # Remove hop-by-hop headers or headers that will cause validation errors upstream
        hop_by_hop = {
            "host",
            "content-length",
            "transfer-encoding",
            "connection",
            "keep-alive",
            "proxy-authenticate",
            "proxy-authorization",
            "te",
            "trailers",
            "upgrade",
        }
        for header in hop_by_hop:
            headers.pop(header, None)

        # Inject extra headers if provided (e.g., modified authorization or tracing IDs)
        if extra_headers:
            headers.update(extra_headers)

        # Use modified body if provided, otherwise stream/read original
        content = modified_body
        if content is None:
            content = await request.body()

        # Build upstream target URL preserving query parameters
        query_params = request.url.query
        full_url = f"{upstream_url}?{query_params}" if query_params else upstream_url

        try:
            # Create outgoing request
            req = self._client.build_request(
                method=request.method,
                url=full_url,
                headers=headers,
                content=content
            )

            # Send request and receive response headers/status without fully loading the body yet
            response = await self._client.send(req, stream=True)

            # Extract response headers
            resp_headers = dict(response.headers)
            
            # Clean up response hop-by-hop headers
            for header in hop_by_hop:
                resp_headers.pop(header, None)

            # Check if the response is Server-Sent Events (SSE) streaming
            content_type = resp_headers.get("content-type", "")
            is_sse = "text/event-stream" in content_type

            if is_sse:
                async def stream_generator() -> AsyncGenerator[bytes, None]:
                    try:
                        async for chunk in response.aiter_bytes():
                            yield chunk
                    except Exception as e:
                        logger.error(f"Error during SSE stream forwarding: {e}")
                        raise
                    finally:
                        await response.aclose()

                return StreamingResponse(
                    stream_generator(),
                    status_code=response.status_code,
                    headers=resp_headers,
                    media_type="text/event-stream"
                )
            else:
                # Standard response, read fully
                response_body = await response.aread()
                await response.aclose()

                return Response(
                    content=response_body,
                    status_code=response.status_code,
                    headers=resp_headers,
                    media_type=content_type if content_type else None
                )

        except httpx.TimeoutException as te:
            logger.error(f"Upstream request timeout for {upstream_url}: {te}")
            return Response(
                content=b'{"error": {"message": "Agent Firewall: Upstream timeout", "type": "timeout_error"}}',
                status_code=504,
                media_type="application/json"
            )
        except httpx.RequestError as re:
            logger.error(f"Upstream connection error for {upstream_url}: {re}")
            return Response(
                content=f'{{"error": {{"message": "Agent Firewall: Upstream connection failed: {str(re)}", "type": "connection_error"}}}}'.encode("utf-8"),
                status_code=502,
                media_type="application/json"
            )
        except Exception as e:
            logger.exception(f"Unexpected error forwarding request to {upstream_url}: {e}")
            return Response(
                content=f'{{"error": {{"message": "Agent Firewall: Internal proxy error: {str(e)}", "type": "internal_error"}}}}'.encode("utf-8"),
                status_code=500,
                media_type="application/json"
            )
