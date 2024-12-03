# phishing_detection_service/urls.py
"""
URL Configuration for Phishing Detection Service

This module defines the URL routing for the phishing detection application,
providing a clear and structured path for URL analysis endpoints.

:module: phishing_detection_service.urls
:author: lx

"""

from django.urls import path
from django.core.exceptions import ValidationError
from django.http import HttpResponseBadRequest

from .views import URLAnalysisView

# Type hints for clearer code structure
from typing import List, Union
from django.urls.resolvers import URLPattern

def validate_url_patterns(urlpatterns: List[Union[URLPattern, None]]) -> List[Union[URLPattern, None]]:
    """
    Validate and sanitize URL patterns before adding them to the routing configuration.

    This function ensures that only valid URL patterns are included in the routing,
    providing an additional layer of security and configuration validation.

    :param urlpatterns: A list of URL patterns to be validated
    :type urlpatterns: List[Union[URLPattern, None]]
    :returns: A validated list of URL patterns
    :rtype: List[Union[URLPattern, None]]
    :raises ValidationError: If an invalid URL pattern is detected
    """
    try:
        # Perform basic validation on URL patterns
        validated_patterns = [
            pattern for pattern in urlpatterns 
            if pattern is not None  # Remove any None entries
        ]

        if not validated_patterns:
            raise ValidationError("No valid URL patterns found.")

        return validated_patterns

    except Exception as e:
        # Log the error for debugging purposes
        print(f"URL Pattern Validation Error: {e}")
        raise ValidationError(f"Invalid URL configuration: {e}")

try:
    # Main URL patterns for the phishing detection service
    urlpatterns: List[Union[URLPattern, None]] = validate_url_patterns([
        # URL route for analyzing URLs
        path(
            'analyze/',  # Endpoint path
            URLAnalysisView.as_view(),  # View handler
            name='analyze-url'  # Named route for reverse lookup
        ),
        # Potential future routes can be added here with the same validation
    ])

except ValidationError as ve:
    # Handle configuration errors gracefully
    print(f"URL Configuration Error: {ve}")
    urlpatterns = []  # Ensure empty urlpatterns to prevent server startup failure
