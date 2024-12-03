# phishing_detection_service/urls.py

"""
URL Routing
-----------
Defines routes for the phishing detection app.
"""

from django.urls import path
from .views import URLAnalysisView

urlpatterns = [
    path('analyze/', URLAnalysisView.as_view(), name='analyze-url'),
]

