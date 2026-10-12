import json
import logging
from typing import AsyncGenerator, Dict, Any, Optional, Tuple

logger = logging.getLogger("agent_firewall.budget.tracker")

class TokenTracker:
    """
    Parses and tracks real-time token consumption from OpenAI and Anthropic 
    API responses, supporting both JSON payloads and Server-Sent Events (SSE) streams.
    """

    def __init__(self) -> None:
        pass

    @staticmethod
    def count_tokens_json(provider: str, response_data: Dict[str, Any]) -> Tuple[int, int]:
        """
        Extracts prompt/input tokens and completion/output tokens from a standard JSON response.
        
        Args:
            provider: 'openai' or 'anthropic'
            response_data: The parsed JSON response dictionary.
            
        Returns:
            Tuple[int, int]: (prompt_tokens, completion_tokens)
        """
        prompt_tokens = 0
        completion_tokens = 0

        try:
            if provider.lower() == "openai":
                usage = response_data.get("usage", {})
                prompt_tokens = usage.get("prompt_tokens", 0)
                completion_tokens = usage.get("completion_tokens", 0)
            elif provider.lower() == "anthropic":
                usage = response_data.get("usage", {})
                prompt_tokens = usage.get("input_tokens", 0)
                completion_tokens = usage.get("output_tokens", 0)
            else:
                logger.warning(f"Unknown provider for JSON token counting: {provider}")
        except Exception as e:
            logger.error(f"Failed to parse tokens from {provider} JSON response: {e}", exc_info=True)

        return prompt_tokens, completion_tokens

    async def parse_sse_stream(
        self, provider: str, stream: AsyncGenerator[bytes, None]
    ) -> AsyncGenerator[Tuple[bytes, int, int], None]:
        """
        Consumes an SSE byte stream, yields chunks untouched, and accumulates 
        real-time token metrics parsed from event chunks.
        
        Args:
            provider: 'openai' or 'anthropic'
            stream: Async generator yielding raw bytes from the upstream API.
            
        Yields:
            Tuple[bytes, int, int]: (raw_chunk_bytes, incremental_prompt_tokens, incremental_completion_tokens)
        """
        buffer = b""
        
        try:
            async for raw_chunk in stream:
                buffer += raw_chunk
                prompt_inc = 0
                completion_inc = 0

                # Process complete lines in the buffer
                while b"\n" in buffer:
                    line, buffer = buffer.split(b"\n", 1)
                    line = line.strip()
                    
                    if not line or line.startswith(b":"):
                        continue  # Comments or empty lines

                    if line.startswith(b"data: "):
                        data_str = line[6:].decode("utf-8", errors="ignore")
                        if data_str == "[DONE]":
                            continue

                        try:
                            event_data = json.loads(data_str)
                            p_tokens, c_tokens = self._extract_sse_usage(provider, event_data)
                            prompt_inc += p_tokens
                            completion_inc += c_tokens
                        except json.JSONDecodeError:
                            continue
                        except Exception as e:
                            logger.debug(f"Error parsing SSE data line: {e}")

                yield raw_chunk, prompt_inc, completion_inc

        except Exception as e:
            logger.error(f"Error reading SSE stream for {provider}: {e}", exc_info=True)
            raise

    def _extract_sse_usage(self, provider: str, event_data: Dict[str, Any]) -> Tuple[int, int]:
        """
        Extracts usage metrics from a single parsed SSE event payload.
        """
        prompt_tokens = 0
        completion_tokens = 0

        if provider.lower() == "openai":
            # OpenAI sometimes includes usage in the final chunk if stream_options: {"include_usage": true} is set
            usage = event_data.get("usage")
            if usage:
                prompt_tokens = usage.get("prompt_tokens", 0)
                completion_tokens = usage.get("completion_tokens", 0)

        elif provider.lower() == "anthropic":
            # Anthropic sends usage across different event types: message_start, message_delta
            event_type = event_data.get("type")
            if event_type == "message_start":
                message = event_data.get("message", {})
                usage = message.get("usage", {})
                prompt_tokens = usage.get("input_tokens", 0)
                completion_tokens = usage.get("output_tokens", 0)
            elif event_type == "message_delta":
                usage = event_data.get("usage", {})
                completion_tokens = usage.get("output_tokens", 0)
            elif event_type == "ping":
                pass

        return prompt_tokens, completion_tokens
