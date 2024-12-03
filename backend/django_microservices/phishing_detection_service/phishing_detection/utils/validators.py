"""
Validation Utilities
--------------------
Provides helper functions for input validation.
"""

import validators
from .logger import get_logger

logger = get_logger(__name__)

def validate_url(url: str):
    """
    Validates the provided URL.

    Args:
        url (str): The URL to validate.

    Raises:
        ValueError: If the URL is invalid.
    """
    if not validators.url(url):
        logger.warning(f"Invalid URL received: {url}")
        raise ValueError("Invalid URL provided.")
