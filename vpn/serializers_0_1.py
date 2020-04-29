from rest_framework import serializers
from rest_framework_friendly_errors.mixins import FriendlyErrorMessagesMixin
from .models import (
    VpnClientEvent,
)


class VpnClientEventSerializer(FriendlyErrorMessagesMixin, serializers.ModelSerializer):
    """Serializer for the VpnClientEvent model."""

    class Meta:
        """Meta."""

        model = VpnClientEvent
        fields = [
            'public_key',
            'error',
            'client_software_version',
            'client_os',
            'client_os_version',
            'local_timestamp',
            'ip4_address',
            'ip6_address',
            'message',
            'debugging_messages'
        ]
