"""
Detection Result Model

Defines the database model for storing phishing detection analysis results
with comprehensive validation and robust error handling.

:module: phishing_detection_service.models
:author: lx

"""

import re
from typing import Optional, Union
from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

class RiskLevelChoices(models.TextChoices):
    """
    Enumeration of possible risk level classifications.

    Provides a standardized set of risk levels for consistent 
    phishing detection result reporting.
    """
    SAFE = 'Safe', _('Safe')
    SUSPICIOUS = 'Suspicious', _('Suspicious')
    PHISHING = 'Phishing', _('Phishing')
    UNKNOWN = 'Unknown', _('Unknown')

class DetectionResult(models.Model):
    """
    Comprehensive model for storing and managing phishing detection results.

    Captures detailed information about URL analysis, including:
    - URL being analyzed
    - Risk classification
    - Trust/confidence score
    - Timestamp of analysis

    Attributes:
        url (URLField): The fully qualified URL that was analyzed
        risk_level (CharField): Classification of URL risk
        trust_score (FloatField): Numeric representation of phishing probability
        analyzed_at (DateTimeField): Precise timestamp of analysis
    """

    url = models.URLField(
        verbose_name=_('Analyzed URL'),
        max_length=2048,  # Extended max length for long URLs
        help_text=_('The complete URL that was analyzed for phishing threats')
    )

    risk_level = models.CharField(
        verbose_name=_('Risk Level'),
        max_length=20,
        choices=RiskLevelChoices.choices,
        default=RiskLevelChoices.UNKNOWN,
        help_text=_('Risk classification of the analyzed URL')
    )

    trust_score = models.FloatField(
        verbose_name=_('Trust Score'),
        help_text=_('Probability of the URL being a phishing threat (0.0 - 1.0)'),
        validators=[
            # Custom validator to ensure trust score is within valid range
            lambda value: DetectionResult.validate_trust_score(value)
        ]
    )

    analyzed_at = models.DateTimeField(
        verbose_name=_('Analysis Timestamp'),
        default=timezone.now,
        help_text=_('Precise time when the URL was analyzed')
    )

    class Meta:
        """
        Model-level metadata and constraints.

        Defines indexes, ordering, and other database-level configurations.
        """
        verbose_name = _('Detection Result')
        verbose_name_plural = _('Detection Results')
        ordering = ['-analyzed_at']  # Most recent results first
        indexes = [
            models.Index(fields=['url', 'analyzed_at']),
            models.Index(fields=['risk_level', 'trust_score'])
        ]

    def clean(self) -> None:
        """
        Perform model-level validation before saving.

        Validates:
        - URL format
        - Trust score range
        - Risk level consistency
        
        Raises:
            ValidationError: If any validation checks fail
        """
        super().clean()
        
        # Validate URL format
        if not self._is_valid_url(self.url):
            raise ValidationError({
                'url': _('Invalid URL format. Please provide a valid, fully qualified URL.')
            })

        # Cross-validate trust score and risk level
        if self.risk_level == RiskLevelChoices.SAFE and self.trust_score > 0.3:
            raise ValidationError({
                'trust_score': _('Trust score is inconsistent with Safe risk level.')
            })
        
        if self.risk_level == RiskLevelChoices.PHISHING and self.trust_score < 0.7:
            raise ValidationError({
                'trust_score': _('Trust score is inconsistent with Phishing risk level.')
            })

    def save(self, *args, **kwargs):
        """
        Override save method to ensure data integrity.

        Performs full validation and sets default values if needed.
        
        Args:
            *args: Positional arguments for model save
            **kwargs: Keyword arguments for model save
        """
        self.full_clean()  # Trigger model-level validation
        super().save(*args, **kwargs)

    @staticmethod
    def validate_trust_score(value: float) -> None:
        """
        Validate the trust score against predefined constraints.

        Args:
            value (float): Trust score to validate

        Raises:
            ValidationError: If trust score is outside valid range [0.0, 1.0]
        """
        if not (0.0 <= value <= 1.0):
            raise ValidationError(
                _('Trust score must be between 0.0 and 1.0.')
            )

    @staticmethod
    def _is_valid_url(url: str) -> bool:
        """
        Perform comprehensive URL validation.

        Args:
            url (str): URL to validate

        Returns:
            bool: True if URL is valid, False otherwise
        """
        # Basic regex for URL validation
        url_pattern = re.compile(
            r'^https?://'  # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
            r'localhost|'  # localhost...
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or IP
            r'(?::\d+)?'  # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE
        )
        return bool(url_pattern.match(url))

    def __str__(self) -> str:
        """
        String representation of the detection result.

        Returns:
            str: Formatted string with URL, risk level, and trust score
        """
        return _('{url} - {risk_level} (Trust: {trust_score:.2f})').format(
            url=self.url,
            risk_level=self.risk_level,
            trust_score=self.trust_score
        )