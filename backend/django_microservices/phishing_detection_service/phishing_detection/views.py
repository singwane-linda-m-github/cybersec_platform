"""
Django Views for Phishing URL Detection

This module provides API views for processing and analyzing URLs 
to detect potential phishing threats.

:module: phishing_detection_service.views
:author: lx
:license: MIT
:copyright: (c) 2024 Phishing Detection Project
"""

import logging
from typing import Dict, Any, Optional

from rest_framework import status
from rest_framework.views import APIView
from rest_framework.request import Request
from rest_framework.response import Response

from .logic.detector import PhishingDetector
from .utils.validators import validate_url
from .utils.exceptions import (
    InvalidURLError, 
    PhishingDetectionError, 
    ServiceUnavailableError
)

# Configure logging for comprehensive error tracking
logger = logging.getLogger(__name__)

class URLAnalysisView(APIView):
    """
    API endpoint for comprehensive URL phishing analysis.

    This view handles URL submission, validation, and phishing detection,
    providing a robust and secure mechanism for analyzing potential 
    phishing threats.

    :ivar detector: PhishingDetector instance for URL analysis
    :type detector: PhishingDetector
    """

    def __init__(self, *args, **kwargs):
        """
        Initialize the URLAnalysisView with a PhishingDetector.

        Ensures that a detector is ready for URL analysis upon 
        view instantiation.

        :param args: Positional arguments passed to parent class
        :param kwargs: Keyword arguments passed to parent class
        """
        super().__init__(*args, **kwargs)
        self.detector = PhishingDetector()

    def post(self, request: Request) -> Response:
        """
        Process POST requests for URL phishing analysis.

        Performs a comprehensive workflow:
        1. Extract URL from request
        2. Validate URL format
        3. Analyze URL for phishing indicators
        4. Return structured analysis results
        5. Handle various potential error scenarios

        :param request: Incoming HTTP request
        :type request: Request
        :returns: Structured JSON response with analysis results
        :rtype: Response
        """
        try:
            # 1. Extract URL from request payload
            url = self._extract_url(request)

            # 2. Validate URL format and structure
            validate_url(url)

            # 3. Perform phishing detection analysis
            result = self._analyze_url(url)

            # 4. Return successful analysis response
            return Response(
                data=result, 
                status=status.HTTP_200_OK
            )

        except InvalidURLError as invalid_url_error:
            # Handle invalid URL format errors
            return self._handle_invalid_url_error(invalid_url_error)

        except PhishingDetectionError as detection_error:
            # Handle errors during phishing detection process
            return self._handle_detection_error(detection_error)

        except ServiceUnavailableError as service_error:
            # Handle service-level unavailability or configuration issues
            return self._handle_service_error(service_error)

        except Exception as unexpected_error:
            # Catch and log any unexpected errors
            return self._handle_unexpected_error(unexpected_error)

    def _extract_url(self, request: Request) -> str:
        """
        Extract URL from request payload with stringent validation.

        :param request: Incoming HTTP request
        :type request: Request
        :returns: Extracted URL string
        :rtype: str
        :raises InvalidURLError: If no URL is provided
        """
        url = request.data.get("url", "").strip()
        if not url:
            raise InvalidURLError("No URL provided in request")
        return url

    def _analyze_url(self, url: str) -> Dict[str, Any]:
        """
        Conduct comprehensive URL phishing analysis.

        :param url: URL to be analyzed
        :type url: str
        :returns: Analysis results dictionary
        :rtype: Dict[str, Any]
        :raises PhishingDetectionError: If analysis encounters issues
        """
        try:
            return self.detector.analyze_url(url)
        except Exception as e:
            logger.error(f"URL analysis failed: {e}")
            raise PhishingDetectionError(f"Analysis failed: {str(e)}")

    def _handle_invalid_url_error(self, error: InvalidURLError) -> Response:
        """
        Handle and log invalid URL errors.

        :param error: Caught InvalidURLError
        :type error: InvalidURLError
        :returns: Error response
        :rtype: Response
        """
        logger.warning(f"Invalid URL submission: {error}")
        return Response(
            data={"error": str(error)}, 
            status=status.HTTP_400_BAD_REQUEST
        )

    def _handle_detection_error(self, error: PhishingDetectionError) -> Response:
        """
        Handle phishing detection process errors.

        :param error: Caught PhishingDetectionError
        :type error: PhishingDetectionError
        :returns: Error response
        :rtype: Response
        """
        logger.error(f"Phishing detection error: {error}")
        return Response(
            data={"error": "Phishing detection failed"}, 
            status=status.HTTP_422_UNPROCESSABLE_ENTITY
        )

    def _handle_service_error(self, error: ServiceUnavailableError) -> Response:
        """
        Handle service-level unavailability errors.

        :param error: Caught ServiceUnavailableError
        :type error: ServiceUnavailableError
        :returns: Error response
        :rtype: Response
        """
        logger.critical(f"Service unavailable: {error}")
        return Response(
            data={"error": "Service currently unavailable"}, 
            status=status.HTTP_503_SERVICE_UNAVAILABLE
        )

    def _handle_unexpected_error(self, error: Exception) -> Response:
        """
        Handle and log any unexpected errors.

        :param error: Caught unexpected Exception
        :type error: Exception
        :returns: Generic error response
        :rtype: Response
        """
        logger.exception(f"Unexpected error in URL analysis: {error}")
        return Response(
            data={"error": "An unexpected error occurred"}, 
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )