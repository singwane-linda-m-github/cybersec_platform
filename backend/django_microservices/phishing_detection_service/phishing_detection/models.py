from django.db import models

class DetectionResult(models.Model):
    """
    Model to store phishing detection results.

    Attributes:
        url (str): The analyzed URL.
        risk_level (str): Risk classification (Safe/Suspicious/Phishing).
        trust_score (float): Phishing probability score.
        analyzed_at (datetime): Timestamp of analysis.
    """
    url = models.URLField()
    risk_level = models.CharField(max_length=20)
    trust_score = models.FloatField()
    analyzed_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.url} - {self.risk_level} ({self.trust_score:.2f})"
