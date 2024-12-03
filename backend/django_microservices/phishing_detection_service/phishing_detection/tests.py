"""
URL Analysis Tests

Comprehensive test suite for phishing detection service,
covering various URL analysis scenarios.

:module: phishing_detection.tests
:author: lx


Future Recommendations:

Ensure the URL analysis view and detector logic match these test expectations
Add more edge case tests as the application evolves
Consider parameterized testing for multiple URL scenarios
"""

import logging
from django.test import TestCase
from rest_framework.test import APIClient, APIRequestFactory
from rest_framework import status
from unittest.mock import patch, Mock

from .views import URLAnalysisView
from .utils.exceptions import (
    InvalidURLError, 
    PhishingDetectionError, 
    ServiceUnavailableError
)

# Configure logger for test-specific logging
logger = logging.getLogger(__name__)

class URLAnalysisTests(TestCase):
    """
    Comprehensive test suite for URL analysis functionality.

    Covers multiple scenarios including:
    - Safe URL detection
    - Phishing URL detection
    - Invalid URL handling
    - Error scenario management
    """

    def setUp(self):
        """
        Prepare test environment before each test method.

        Sets up APIClient for making test requests and 
        initializes the URLAnalysisView for detailed testing.
        """
        self.client = APIClient()
        self.view = URLAnalysisView()
        self.factory = APIRequestFactory()

    def test_safe_url(self):
        """
        Test analysis of a known safe URL.

        Verifies:
        - Correct HTTP status code
        - Accurate "Safe" classification
        """
        # Mock the detector to return a safe URL result
        with patch.object(self.view.detector, 'analyze_url', return_value={
            'status': 'Safe',
            'confidence_score': 0.1
        }) as mock_analyze:
            response = self.client.post('/analyze/', 
                                        {"url": "http://example.com"}, 
                                        format="json")
            
            # Assertions
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertEqual(response.data["status"], "Safe")
            mock_analyze.assert_called_once_with("http://example.com")

    def test_invalid_url(self):
        """
        Test handling of invalid URL submissions.

        Verifies:
        - Correct HTTP error status
        - Appropriate error message
        """
        response = self.client.post('/analyze/', 
                                    {"url": "invalid-url"}, 
                                    format="json")
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response.data)

    def test_phishing_url(self):
        """
        Test analysis of a suspected phishing URL.

        Verifies:
        - Correct HTTP status code
        - Accurate "Phishing" classification
        """
        # Mock the detector to return a phishing URL result
        with patch.object(self.view.detector, 'analyze_url', return_value={
            'status': 'Phishing',
            'confidence_score': 0.9
        }) as mock_analyze:
            response = self.client.post('/analyze/', 
                                        {"url": "http://phishing.com/@bank"}, 
                                        format="json")
            
            # Assertions
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertEqual(response.data["status"], "Phishing")
            mock_analyze.assert_called_once_with("http://phishing.com/@bank")

    def test_empty_url_submission(self):
        """
        Test handling of empty URL submissions.

        Verifies:
        - Proper error handling
        - Appropriate HTTP error status
        """
        response = self.client.post('/analyze/', 
                                    {"url": ""}, 
                                    format="json")
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response.data)

    def test_malformed_request(self):
        """
        Test handling of malformed or incomplete requests.

        Verifies:
        - Proper error handling for requests without URL
        - Appropriate HTTP error status
        """
        response = self.client.post('/analyze/', 
                                    {}, 
                                    format="json")
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response.data)

    def test_url_detection_error(self):
        """
        Test handling of internal detection errors.

        Verifies:
        - Proper error handling for detection failures
        - Appropriate HTTP error status
        """
        # Simulate a PhishingDetectionError
        with patch.object(self.view.detector, 'analyze_url', 
                          side_effect=PhishingDetectionError("Detection failed")):
            response = self.client.post('/analyze/', 
                                        {"url": "http://example.com"}, 
                                        format="json")
            
            self.assertEqual(response.status_code, status.HTTP_422_UNPROCESSABLE_ENTITY)
            self.assertIn('error', response.data)

    def test_service_unavailable(self):
        """
        Test handling of service unavailability.

        Verifies:
        - Proper error handling for service-level issues
        - Appropriate HTTP service unavailable status
        """
        # Simulate a ServiceUnavailableError
        with patch.object(self.view.detector, 'analyze_url', 
                          side_effect=ServiceUnavailableError("Service down")):
            response = self.client.post('/analyze/', 
                                        {"url": "http://example.com"}, 
                                        format="json")
            
            self.assertEqual(response.status_code, status.HTTP_503_SERVICE_UNAVAILABLE)
            self.assertIn('error', response.data)

