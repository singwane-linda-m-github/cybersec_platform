"""
URL Request Serialization Module

Provides robust serialization and validation for URL analysis requests,
ensuring data integrity and comprehensive error handling.

:module: phishing_detection_service.serializers
:author: Development Team

Key Enhancements:

Comprehensive Validation:

Multi-layered URL validation
Normalization of URL input
Security-focused checks
Protocol validation


Robust Error Handling:

Detailed error messages
Custom validation methods
Handling of various validation scenarios


Security Considerations:

Checks for suspicious URL patterns
Enforces HTTPS
Prevents potential injection risks


Internationalization Support:

Uses gettext_lazy for translatable error messages
Prepared for multilingual support


Additional Serializer Methods:

create() method for data processing
to_representation() for standardized output
Flexible handling of URL data


Type Hinting and Documentation:

Comprehensive type annotations
Detailed Sphinx-style docstrings
Clear explanation of validation steps



Recommendations:

Integrate with logging system for tracking validation events
Consider adding more sophisticated URL validation if needed
Potentially expand security checks based on specific use cases
"""

import re
from urllib.parse import urlparse
from typing import Dict, Any, Optional

from rest_framework import serializers
from rest_framework.exceptions import ValidationError

from django.utils.translation import gettext_lazy as _
from django.core.validators import URLValidator
from django.core.exceptions import ValidationError as DjangoValidationError
from django.utils import timezone

class URLRequestSerializer(serializers.Serializer):
    """
    Comprehensive serializer for URL detection request validation.

    Performs multi-layered validation of submitted URLs, including:
    - Basic URL format checking
    - Protocol validation
    - Comprehensive security checks
    - Normalization of URL input

    Attributes:
        url (serializers.URLField): Field for submitted URL analysis request
    """

    url = serializers.URLField(
        required=True,
        trim_whitespace=True,
        help_text=_('Fully qualified URL to be analyzed for phishing threats'),
        error_messages={
            'required': _('URL is required for analysis.'),
            'invalid': _('Invalid URL format. Please provide a valid, fully qualified URL.')
        }
    )

    def validate_url(self, value: str) -> str:
        """
        Perform comprehensive URL validation with multiple checks.

        Validates:
        - Basic URL structure
        - Supported protocols
        - Potential security risks
        - URL normalization

        Args:
            value (str): Raw URL submitted for analysis

        Returns:
            str: Normalized, validated URL

        Raises:
            ValidationError: If URL fails any validation checks
        """
        try:
            # Trim and normalize URL
            normalized_url = self._normalize_url(value)

            # Perform Django's built-in URL validation
            django_url_validator = URLValidator()
            django_url_validator(normalized_url)

            # Additional custom validations
            self._validate_url_security(normalized_url)
            self._validate_url_protocol(normalized_url)

            return normalized_url

        except DjangoValidationError as e:
            raise ValidationError(
                detail={
                    'url': _('Invalid URL: {}').format(str(e))
                }
            )
        except ValueError as ve:
            raise ValidationError(
                detail={
                    'url': _('URL validation failed: {}').format(str(ve))
                }
            )

    def _normalize_url(self, url: str) -> str:
        """
        Normalize and standardize the submitted URL.

        Performs:
        - Whitespace removal
        - Lowercasing
        - Protocol standardization

        Args:
            url (str): Raw URL input

        Returns:
            str: Normalized URL

        Raises:
            ValueError: If URL cannot be normalized
        """
        try:
            # Remove leading/trailing whitespaces
            url = url.strip()

            # Ensure lowercase for consistency
            url = url.lower()

            # Add default protocol if missing
            if not url.startswith(('http://', 'https://')):
                url = f'https://{url}'

            return url

        except Exception as e:
            raise ValueError(f"URL normalization failed: {e}")

    def _validate_url_security(self, url: str) -> None:
        """
        Perform security-focused URL validation.

        Checks for:
        - Suspicious characters
        - Potential phishing indicators
        - Malformed URL structures

        Args:
            url (str): Normalized URL to validate

        Raises:
            ValidationError: If security risks are detected
        """
        # Check for suspicious characters or patterns
        suspicious_patterns = [
            r'@',           # Potential credential embedding
            r'\s',          # Whitespace in URL
            r'[<>"\']',     # Potential XSS indicators
            r'javascript:',  # Script injection risk
        ]

        for pattern in suspicious_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                raise ValidationError(
                    detail={
                        'url': _('Potential security risk detected in URL.')
                    }
                )

    def _validate_url_protocol(self, url: str) -> None:
        """
        Validate URL protocol and ensure secure connection.

        Verifies:
        - Supported protocols
        - HTTPS preference

        Args:
            url (str): Normalized URL to validate

        Raises:
            ValidationError: If protocol is unsupported or insecure
        """
        parsed_url = urlparse(url)

        # Restrict to HTTPS
        if parsed_url.scheme not in ['https']:
            raise ValidationError(
                detail={
                    'url': _('Only HTTPS URLs are accepted for analysis.')
                }
            )

    def create(self, validated_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create method for serializer to process validated data.

        Provides a hook for additional processing or transformation
        of validated URL data.

        Args:
            validated_data (Dict[str, Any]): Validated serializer data

        Returns:
            Dict[str, Any]: Processed URL data
        """
        return {
            'url': validated_data.get('url'),
            'timestamp': timezone.now()
        }

    def to_representation(self, instance: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Convert serialized data to a standardized representation.

        Provides a consistent output format for API responses.

        Args:
            instance (Optional[Dict[str, Any]], optional): Instance to represent

        Returns:
            Dict[str, Any]: Standardized representation of URL data
        """
        return {
            'url': instance.get('url') if instance else None,
            'normalized_url': self.validated_data.get('url') if hasattr(self, 'validated_data') else None
        }