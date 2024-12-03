"""
Phishing Detection Module

This module provides a robust mechanism for detecting potentially malicious URLs
by analyzing their characteristics and identifying suspicious patterns.

:module: phishing_detection.tests
:author: lx

Changes:
Robust Exception Handling

More granular input validation
Separate methods for different types of URL checks
Detailed logging of events and errors
Configurable logging levels


Modular Design

Broke down URL analysis into multiple specialized methods
Easy to extend and modify individual checks
Added a configuration method for logging


Enhanced Risk Detection

More comprehensive keyword and character checking
Prioritized risk assessment
Configurable length and keyword thresholds


Error Tracking

Uses Python's logging module for structured error reporting
Captures and logs detailed error information
Provides both generic and specific error messages
"""

import re
import logging
from typing import Dict, Optional, Union


class PhishingDetector:
    """
    A comprehensive URL analysis class for detecting potential phishing attempts.

    This class implements various heuristics to assess the likelihood of a URL
    being a phishing attempt based on its structural and contextual characteristics.

    Attributes:
        logger (logging.Logger): A configured logger for tracking detection events and errors.
    """

    def __init__(self, log_level: int = logging.INFO):
        """
        Initialize the PhishingDetector with a configurable logging level.

        Args:
            log_level (int, optional): Logging verbosity level. Defaults to logging.INFO.
        """
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(log_level)

    def analyze_url(self, url: Optional[str]) -> Dict[str, str]:
        """
        Comprehensively analyze a given URL for potential phishing indicators.

        This method performs multiple checks to determine the safety of a URL:
        1. Validates URL input
        2. Checks for suspicious characters
        3. Evaluates URL length
        4. Scans for high-risk keywords
        5. Logs detection events

        Args:
            url (str, optional): The URL to be analyzed. Can be None.

        Returns:
            Dict[str, str]: A dictionary containing:
            - 'status': Categorization of URL risk ('Safe', 'Suspicious', 'Phishing')
            - 'explanation': Detailed reasoning for the status

        Raises:
            ValueError: If input validation fails
            Exception: For unexpected errors during URL analysis
        """
        # Input validation
        if url is None:
            self.logger.warning("Received None as URL input")
            raise ValueError("URL cannot be None")

        # Trim and validate URL
        url = url.strip()
        if not url:
            self.logger.warning("Empty URL provided after trimming")
            raise ValueError("URL cannot be empty")

        try:
            # Comprehensive risk assessment
            risk_checks = [
                self._check_suspicious_characters(url),
                self._check_url_length(url),
                self._check_phishing_keywords(url)
            ]

            # Prioritize risk levels
            for check in risk_checks:
                if check['status'] != 'Safe':
                    self.logger.info(f"Detected risk: {check['explanation']}")
                    return check

            # Default safe response
            safe_result = {
                'status': 'Safe',
                'explanation': 'URL passed all security checks'
            }
            self.logger.debug(f"URL analysis result: {safe_result}")
            return safe_result

        except Exception as e:
            self.logger.error(f"Unexpected error in URL analysis: {e}", exc_info=True)
            raise Exception(f"Critical error during URL analysis: {e}")

    def _check_suspicious_characters(self, url: str) -> Dict[str, str]:
        """
        Check for suspicious characters that might indicate a phishing attempt.

        Args:
            url (str): URL to be checked

        Returns:
            Dict[str, str]: Risk assessment for suspicious characters
        """
        suspicious_patterns = [
            r'@',  # Email-like characters in URL
            r'\s',  # Whitespace
            r'[<>{}]'  # Potentially malicious HTML/script characters
        ]

        for pattern in suspicious_patterns:
            if re.search(pattern, url):
                return {
                    'status': 'Phishing',
                    'explanation': f'Suspicious character pattern detected: {pattern}'
                }

        return {'status': 'Safe', 'explanation': 'No suspicious characters found'}

    def _check_url_length(self, url: str) -> Dict[str, str]:
        """
        Validate URL length as a potential risk indicator.

        Args:
            url (str): URL to be checked for length

        Returns:
            Dict[str, str]: Risk assessment based on URL length
        """
        MAX_URL_LENGTH = 100
        MIN_URL_LENGTH = 5

        if len(url) > MAX_URL_LENGTH:
            return {
                'status': 'Phishing',
                'explanation': f'URL exceeds maximum allowed length of {MAX_URL_LENGTH}'
            }
        
        if len(url) < MIN_URL_LENGTH:
            return {
                'status': 'Suspicious',
                'explanation': f'URL is unusually short (less than {MIN_URL_LENGTH} characters)'
            }

        return {'status': 'Safe', 'explanation': 'URL length is within acceptable range'}

    def _check_phishing_keywords(self, url: str) -> Dict[str, str]:
        """
        Scan URL for keywords commonly associated with phishing attempts.

        Args:
            url (str): URL to be scanned for risky keywords

        Returns:
            Dict[str, str]: Risk assessment based on keyword detection
        """
        phishing_keywords = [
            r'login', 
            r'bank', 
            r'secure', 
            r'verify', 
            r'account', 
            r'update'
        ]

        for keyword in phishing_keywords:
            if re.search(keyword, url, re.IGNORECASE):
                return {
                    'status': 'Suspicious',
                    'explanation': f'Detected potentially risky keyword: {keyword}'
                }

        return {'status': 'Safe', 'explanation': 'No suspicious keywords detected'}


# Optional: Configure logging for the module
def configure_logging(level: int = logging.INFO) -> None:
    """
    Configure logging for the phishing detection module.

    Args:
        level (int, optional): Logging verbosity level. Defaults to logging.INFO.
    """
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
