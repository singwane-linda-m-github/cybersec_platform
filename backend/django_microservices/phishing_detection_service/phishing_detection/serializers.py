from rest_framework import serializers

class URLRequestSerializer(serializers.Serializer):
    """
    Serializer for validating URL detection requests.

    Attributes:
        url (str): The URL to be analyzed.
    """
    url = serializers.URLField()
