"""
Phishing Detection Logic
------------------------
Handles the detection of phishing URLs with robust exception handling.
"""

import re
from ..utils.logger import get_logger

logger = get_logger(__name__)

class PhishingDetector:
    """  
    Core logic for detecting phishing URLs.
    """

    def analyze_url(self, url: str):
        """
        Analyze a given URL for phishing characteristics.

        Args:
            url (str): The URL to analyze.

        Returns:
            dict: Analysis result with status and explanation.
        """
        try:
            # Check if the URL is empty
            if not url:
                raise ValueError("URL cannot be empty.")

            # Check for suspicious characters or excessively long URLs
            if "@" in url or len(url) > 100:
                return {
                    "status": "Phishing",
                    "explanation": "Suspicious characters or unusually long URL."
                }

            # Check for keywords that might indicate phishing behavior (like login, bank, etc.)
            elif re.search(r"(login|bank|secure)", url, re.IGNORECASE):
                return {
                    "status": "Suspicious",
                    "explanation": "Contains keywords associated with phishing."
                }

            # If no issues found, return "Safe"
            else:
                return {
                    "status": "Safe",
                    "explanation": "URL appears normal."
                }

        except Exception as e:
            logger.error(f"Error analyzing URL: {str(e)}")
            # Raise a generic error message for unexpected issues
            raise Exception("An error occurred during URL analysis.")


