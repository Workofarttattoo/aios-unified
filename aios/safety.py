"""Stub for aios.safety — prompt safety helpers."""
import logging as _logging
_LOG = _logging.getLogger(__name__)

def is_prompt_safe(prompt: str, **kwargs) -> bool:
    """Check if a prompt is safe. Stub always returns True."""
    return True

def sanitize_prompt(prompt: str, **kwargs) -> str:
    """Sanitize a prompt. Stub returns prompt unchanged."""
    return prompt
