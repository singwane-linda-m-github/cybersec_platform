"""
Custom Exception Classes

Defines specific exception types for the phishing detection service
to enable more granular error handling and reporting.

:module: phishing_detection_service.exceptions
:author: lx

"""

class PhishingDetectionBaseError(Exception):
    """
    Base exception for all phishing detection related errors.

    Provides a common base for more specific exception types,
    allowing for hierarchical error handling.
    """
    def __init__(self, message: str = "A phishing detection error occurred"):
        """
        Initialize the base exception with a default or custom message.

        :param message: Descriptive error message
        :type message: str
        """
        self.message = message
        super().__init__(self.message)


class InvalidURLError(PhishingDetectionBaseError):
    """
    Exception raised for invalid URL format or structure.

    Indicates that the provided URL does not meet the required
    validation criteria.
    """
    def __init__(self, message: str = "Invalid URL format"):
        """
        Initialize with a specific invalid URL error message.

        :param message: Detailed description of URL invalidity
        :type message: str
        """
        super().__init__(message)


class PhishingDetectionError(PhishingDetectionBaseError):
    """
    Exception raised during the URL phishing analysis process.

    Indicates failures in detecting or analyzing potential
    phishing indicators.
    """
    def __init__(self, message: str = "Failed to complete phishing detection"):
        """
        Initialize with a specific phishing detection error message.

        :param message: Detailed description of detection failure
        :type message: str
        """
        super().__init__(message)


class ServiceUnavailableError(PhishingDetectionBaseError):
    """
    Exception raised when phishing detection service is unavailable.

    Indicates infrastructure or configuration issues preventing
    the service from functioning.
    """
    def __init__(self, message: str = "Phishing detection service is unavailable"):
        """
        Initialize with a service unavailability error message.

        :param message: Detailed description of service unavailability
        :type message: str
        """
        super().__init__(message)


class RateLimitExceededError(PhishingDetectionBaseError):
    """
    Exception raised when API rate limits are exceeded.

    Indicates that the maximum number of allowed requests
    has been reached.
    """
    def __init__(self, message: str = "API rate limit exceeded"):
        """
        Initialize with a rate limit error message.

        :param message: Detailed description of rate limit exceedance
        :type message: str
        """
        super().__init__(message)
