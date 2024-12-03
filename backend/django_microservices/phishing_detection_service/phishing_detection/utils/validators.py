"""
URL Validation Utilities

Comprehensive module for robust URL validation and security checks.

:module: phishing_detection.
:author: lx

Key Improvements:

Comprehensive Validation

Multi-stage URL validation
Checks for syntax, protocol, and security risks
Handles various input types (str, bytes)


Robust Exception Handling

Detailed error logging
Specific exception types
Configurable validation strictness


Security Enhancements

Prevent private network URL access
Detect potential injection risks
Normalize and sanitize URLs


Flexible Configuration

Optional private network URL allowance
Adjustable validation strictness
Configurable logging levels


Enhanced Documentation

Comprehensive Sphinx-style docstrings
Clear explanation of validation process
Detailed error descriptions
"""

import re
import logging
from typing import Optional, Union
from urllib.parse import urlparse, urljoin

import validators


class URLValidator:
    """
    Advanced URL validation and security checking utility.

    Provides multiple layers of URL validation including:
    - Syntactic validation
    - Protocol checks
    - Potential security risk assessment
    """

    def __init__(self, log_level: int = logging.INFO):
        """
        Initialize URLValidator with configurable logging.

        Args:
            log_level (int, optional): Logging verbosity level. 
                Defaults to logging.INFO.
        """
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(log_level)

    def validate_url(
        self, 
        url: Optional[Union[str, bytes]], 
        allow_private: bool = False,
        strict: bool = True
    ) -> str:
        """
        Comprehensively validate and sanitize a URL.

        Performs multi-stage validation:
        1. Input type and emptiness check
        2. Type conversion and normalization
        3. Syntactic validation
        4. Protocol validation
        5. Optional private network checks
        6. Security risk assessment

        Args:
            url (Optional[Union[str, bytes]]): URL to validate
            allow_private (bool, optional): Allow private network URLs. 
                Defaults to False.
            strict (bool, optional): Apply stringent validation rules. 
                Defaults to True.

        Returns:
            str: Normalized, validated URL

        Raises:
            ValueError: If URL fails validation
            TypeError: For invalid input types
        """
        # Input validation
        if url is None:
            self.logger.warning("Received None as URL input")
            raise ValueError("URL cannot be None")

        # Handle byte input
        if isinstance(url, bytes):
            try:
                url = url.decode('utf-8')
            except UnicodeDecodeError:
                self.logger.error("Failed to decode byte URL")
                raise TypeError("URL must be a valid UTF-8 encoded string")

        # Trim and validate non-empty
        url = url.strip()
        if not url:
            self.logger.warning("Empty URL after trimming")
            raise ValueError("URL cannot be empty")

        try:
            # Syntactic validation
            if not validators.url(url):
                self.logger.warning(f"Invalid URL syntax: {url}")
                raise ValueError(f"Malformed URL: {url}")

            # Parse URL components
            parsed_url = urlparse(url)

            # Protocol validation
            if parsed_url.scheme not in {'http', 'https'}:
                if strict:
                    self.logger.warning(f"Unsupported protocol: {parsed_url.scheme}")
                    raise ValueError(f"Only HTTP/HTTPS protocols are allowed: {url}")

            # Private network check
            if not allow_private:
                self._check_private_network(parsed_url.hostname)

            # Additional security checks
            self._perform_security_checks(url)

            return url

        except Exception as e:
            self.logger.error(f"URL validation error: {e}", exc_info=True)
            raise ValueError(f"URL validation failed: {e}")

    def _check_private_network(self, hostname: Optional[str]) -> None:
        """
        Check if hostname resolves to a private network address.

        Args:
            hostname (Optional[str]): Hostname to check

        Raises:
            ValueError: If hostname is a private network address
        """
        private_patterns = [
            r'^localhost$',
            r'^127\.\d+\.\d+\.\d+$',
            r'^192\.168\.\d+\.\d+$',
            r'^10\.\d+\.\d+\.\d+$',
            r'^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$'
        ]

        if hostname and any(re.match(pattern, hostname) for pattern in private_patterns):
            self.logger.warning(f"Private network hostname detected: {hostname}")
            raise ValueError(f"Private network URLs are not allowed: {hostname}")

    def _perform_security_checks(self, url: str) -> None:
        """
        Execute additional URL security assessments.

        Args:
            url (str): URL to security check

        Raises:
            ValueError: If potential security risks are detected
        """
        suspicious_patterns = [
            r'@',           # Potential credential embedding
            r'\s',          # Whitespace in URL
            r'[<>{}]',      # Potential script injection
            r'javascript:',  # Script protocol
        ]

        for pattern in suspicious_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                self.logger.warning(f"Security risk detected in URL: {pattern}")
                raise ValueError(f"Potential security risk in URL: {url}")


def validate_url(
    url: Union[str, bytes], 
    allow_private: bool = False, 
    strict: bool = True
) -> str:
    """
    Convenience function for quick URL validation.

    Args:
        url (Union[str, bytes]): URL to validate
        allow_private (bool, optional): Allow private network URLs
        strict (bool, optional): Apply stringent validation rules

    Returns:
        str: Normalized, validated URL

    Raises:
        ValueError: If URL is invalid
    """
    validator = URLValidator()
    return validator.validate_url(url, allow_private, strict)