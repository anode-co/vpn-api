from django.contrib import admin
from .models import (
    VpnClientEvent,
    CjdnsVpnServer
)


@admin.register(VpnClientEvent)
class VpnClientEventAdmin(admin.ModelAdmin):
    """Admin represtation of VpnClientEvent."""

    list_display = ('error', 'created_at', 'client_os', 'public_key')
    ordering = ('-created_at', 'error', 'public_key', 'client_os')
    list_filter = ('error', 'client_os', 'client_software_version')
    search_fields = ('error', 'public_key', 'client_os', 'debugging_messages')


@admin.register(CjdnsVpnServer)
class CjdnsVpnServerAdmin(admin.ModelAdmin):
    """Admin represtation of CjdnsVpnServer."""

    list_display = ('name', 'public_key', 'is_approved', 'is_active', 'online_since_datetime', 'last_seen_datetime')
    ordering = ('is_active', 'is_approved', 'last_seen_datetime', 'online_since_datetime', 'name', 'public_key')
    list_filter = ('is_active', 'is_approved', 'online_since_datetime', 'last_seen_datetime')
    search_fields = ('public_key', 'name')
