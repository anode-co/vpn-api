from django.db import models
from django.utils.translation import gettext_lazy as _


class VpnClientEvent(models.Model):
    """VPN Client Event."""

    ERROR_CONNECTION_FAILED = "connection_failed"
    ERROR_DISCONNECTION = "disconnection"
    ERROR_ROUTE_STOPPED = "route_stopped"
    ERROR_CJDNS_CRASH = "cjdns_crash"
    ERROR_VPN_CLIEN_CONNECTED = "connection"
    ERROR_VPN_CLIENT_DISCONNECTED = "disconnection"
    ERROR_OTHER = "other"

    ERROR_CHOICES = [
        (ERROR_CONNECTION_FAILED, _('Could not connect')),
        (ERROR_DISCONNECTION, _('Unexpected disconnection')),
        (ERROR_ROUTE_STOPPED, _('Connected but unable to route traffic')),
        (ERROR_CJDNS_CRASH, _('CJDNS crashed')),
        (ERROR_VPN_CLIEN_CONNECTED, _('VPN client connected')),
        (ERROR_VPN_CLIENT_DISCONNECTED, _('VPN client disconnected')),
        (ERROR_OTHER, _('Other reason')),
    ]

    public_key = models.CharField(max_length=64)
    error = models.CharField(max_length=64, choices=ERROR_CHOICES)
    client_software_version = models.CharField(max_length=32)
    client_os = models.CharField(max_length=32)
    client_os_version = models.CharField(max_length=32)
    local_timestamp = models.DateTimeField()
    ip4_address = models.CharField(max_length=15, null=True, blank=True)
    ip6_address = models.CharField(max_length=50, null=True, blank=True)
    message = models.CharField(max_length=100)
    debugging_messages = models.TextField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        """Represent as String."""
        return "{} on {} {}".format(self.error, self.client_os, self.client_os_version)
