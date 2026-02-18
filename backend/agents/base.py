"""Base agent class for all Claude AI agents."""

import asyncio
import logging
from typing import Dict, Optional, Union

logger = logging.getLogger(__name__)


class BaseAgent:
    """
    Base class providing shared Claude API call logic for all agents.

    Subclasses should set SYSTEM_PROMPT (class-level) or pass system_prompt
    to __init__. The shared _call_claude() method provides:
    - Structured error returns (dict with error/error_message/fallback keys)
      when the API key is missing
    - One retry with a 2-second delay for transient errors
    - Proper logging
    - On success, returns the response text string for backwards compatibility
    """

    SYSTEM_PROMPT: str = ""

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        system_prompt: Optional[str] = None,
    ):
        """
        Initialize the base agent.

        Args:
            api_key: Anthropic API key. Falls back to settings.
            model: Claude model to use. Falls back to settings.
            system_prompt: Override the class-level SYSTEM_PROMPT.
        """
        from config import get_settings

        settings = get_settings()
        self.api_key = api_key or settings.anthropic_api_key
        self.model = model or settings.claude_model
        self.system_prompt = system_prompt if system_prompt is not None else self.SYSTEM_PROMPT

    async def _call_claude(
        self,
        prompt: str,
        max_tokens: int = 4096,
        system_prompt: Optional[str] = None,
    ) -> Union[str, Dict]:
        """
        Call the Claude API with retry logic and structured error handling.

        Args:
            prompt: The user prompt to send.
            max_tokens: Maximum tokens for the response.
            system_prompt: Optional override for the system prompt
                           (used by ThreatHuntAgent for context-specific prompts).

        Returns:
            The response text string on success, or a structured error dict
            with keys ``error``, ``error_message``, and ``fallback``.
        """
        import anthropic

        if not self.api_key:
            logger.error("Anthropic API key not configured")
            return {
                "error": True,
                "error_message": "Anthropic API key not configured",
                "fallback": True,
            }

        effective_system_prompt = system_prompt if system_prompt is not None else self.system_prompt
        last_exception: Optional[Exception] = None

        for attempt in range(2):  # initial attempt + 1 retry
            try:
                client = anthropic.AsyncAnthropic(api_key=self.api_key)
                message = await client.messages.create(
                    model=self.model,
                    max_tokens=max_tokens,
                    system=effective_system_prompt,
                    messages=[{"role": "user", "content": prompt}],
                )
                return message.content[0].text
            except Exception as e:
                last_exception = e
                if attempt == 0:
                    logger.warning(
                        "Claude API call failed (attempt 1/2), retrying in 2s: %s",
                        str(e),
                    )
                    await asyncio.sleep(2)
                else:
                    logger.error(
                        "Claude API call failed after 2 attempts: %s", str(e)
                    )

        return {
            "error": True,
            "error_message": f"Error calling Claude API: {str(last_exception)}",
            "fallback": True,
        }
