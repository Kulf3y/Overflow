import os
from typing import Dict, Any, Optional

import requests


class OpenRouterError(RuntimeError):
    """Base exception for OpenRouter gateway failures."""


class OpenRouterConfigurationError(OpenRouterError):
    """Raised when the gateway is incorrectly configured."""


class OpenRouterGateway:
    """
    Privacy-focused OpenRouter gateway.

    Security properties:
    - Requires an API key.
    - Requests Zero Data Retention (ZDR).
    - Denies provider data collection/training where supported.
    - Disables provider fallback unless explicitly configured.
    - Uses a bounded HTTP timeout.
    - Raises controlled exceptions for HTTP/API failures.
    - Does not log prompts or completions.
    """

    DEFAULT_MODEL = "mistralai/mistral-large-2407"
    DEFAULT_TIMEOUT = (10, 60)

    def __init__(
        self,
        api_key: Optional[str] = None,
        *,
        eu_only: bool = False,
        timeout: tuple[int, int] = DEFAULT_TIMEOUT,
    ):
        self.api_key = api_key or os.getenv("OPENROUTER_API_KEY")

        if not self.api_key:
            raise OpenRouterConfigurationError(
                "OPENROUTER_API_KEY is not configured."
            )

        self.eu_only = eu_only
        self.timeout = timeout

        # OpenRouter provides EU in-region routing through this endpoint.
        # Use it when EU-only processing is an explicit requirement.
        base_url = (
            "https://eu.openrouter.ai/api/v1"
            if eu_only
            else "https://openrouter.ai/api/v1"
        )

        self.url = f"{base_url}/chat/completions"

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://github.com/eu-sovereign-guard",
            "X-Title": "EU Sovereign Guard Proxy",
        }

    def send_safe_request(
        self,
        prompt: str,
        model: Optional[str] = None,
    ) -> Dict[str, Any]:

        if not isinstance(prompt, str) or not prompt.strip():
            raise ValueError("prompt must be a non-empty string")

        selected_model = model or self.DEFAULT_MODEL

        payload = {
            "model": selected_model,
            "messages": [
                {
                    "role": "user",
                    "content": prompt,
                }
            ],

            # Privacy policy is enforced at the routing layer.
            "provider": {
                "zdr": True,
                "data_collection": "deny",
                "allow_fallbacks": False,
            },
        }

        try:
            response = requests.post(
                self.url,
                headers=self._headers(),
                json=payload,
                timeout=self.timeout,
            )

        except requests.Timeout as exc:
            raise OpenRouterError(
                "OpenRouter request timed out."
            ) from exc

        except requests.ConnectionError as exc:
            raise OpenRouterError(
                "Could not connect to OpenRouter."
            ) from exc

        except requests.RequestException as exc:
            raise OpenRouterError(
                "OpenRouter request failed."
            ) from exc

        # Convert HTTP errors into controlled gateway errors.
        if not response.ok:
            raise OpenRouterError(
                f"OpenRouter returned HTTP {response.status_code}."
            )

        try:
            data = response.json()
        except ValueError as exc:
            raise OpenRouterError(
                "OpenRouter returned invalid JSON."
            ) from exc

        if not isinstance(data, dict):
            raise OpenRouterError(
                "OpenRouter returned an unexpected response format."
            )

        return data
