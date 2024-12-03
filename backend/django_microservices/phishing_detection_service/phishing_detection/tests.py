"""
Unit Tests
----------
Tests the phishing detection service.
"""

from django.test import TestCase
from rest_framework.test import APIClient
from rest_framework import status

class URLAnalysisTests(TestCase):
    """
    Tests for the phishing detection API.
    """

    def setUp(self):
        self.client = APIClient()

    def test_safe_url(self):
        response = self.client.post('/analyze/', {"url": "http://example.com"}, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["status"], "Safe")

    def test_invalid_url(self):
        response = self.client.post('/analyze/', {"url": "invalid-url"}, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_phishing_url(self):
        response = self.client.post('/analyze/', {"url": "http://phishing.com/@bank"}, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["status"], "Phishing")

