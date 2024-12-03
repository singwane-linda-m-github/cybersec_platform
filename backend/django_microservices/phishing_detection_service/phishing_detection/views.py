"""
Django Views
------------
Handles incoming requests and manages responses.
"""
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status  # Ensure this is the correct import

from .logic.detector import PhishingDetector
from .utils.validators import validate_url

class URLAnalysisView(APIView):
    """
    API endpoint for analyzing URLs.
    """

    def post(self, request):
        """
        Handle POST requests for URL analysis.

        Args:
            request: HTTP request containing the URL.

        Returns:
            Response: JSON response with analysis results.
        """
        try:
            url = request.data.get("url")
            validate_url(url)

            detector = PhishingDetector()
            result = detector.analyze_url(url)
            return Response(result, status=status.HTTP_200_OK)  # Ensure status is correctly used
        except ValueError as ve:
            return Response({"error": str(ve)}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error": "An unexpected error occurred."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
