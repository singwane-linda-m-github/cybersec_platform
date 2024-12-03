"""phishing_detection_service URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""



"""
Root URL Routing Module

Centralized URL configuration for Django project routing.
Manages top-level URL patterns and application-specific route inclusions.

:module: phishing_detection_service.
:author: lx
"""

from typing import List
from django.contrib import admin
from django.urls import path, include, URLPattern, URLResolver
from django.http import HttpRequest


def get_urlpatterns() -> List[URLPattern | URLResolver]:
    """
    Dynamically generate and configure root URL patterns.

    Provides centralized URL routing with:
    - Admin interface access
    - Modular application route inclusion
    - Potential for future extensibility

    Returns:
        List[Union[URLPattern, URLResolver]]: Configured URL routing patterns
    """
    urlpatterns = [
        # Django admin interface routes
        path('admin/', admin.site.urls),

        # Application-specific route inclusions
        path('phishing/', include('phishing_detection.urls')),
        
        # Placeholder for additional application routes
        # path('api/', include('api.urls')),
    ]

    return urlpatterns


# Assign global urlpatterns for Django's URL dispatcher
urlpatterns = get_urlpatterns()
