from django.contrib import admin
from .models import (
    VpnClientEvent
)


@admin.register(VpnClientEvent)
class VpnClientEventAdmin(admin.ModelAdmin):
    """Admin represtation of VpnClientEvent."""

    list_display = ('error', 'created_at', 'client_os', 'public_key')
    ordering = ('-created_at', 'error', 'public_key', 'client_os')
    list_filter = ('error', 'client_os', 'client_software_version')
    search_fields = ('error', 'public_key', 'client_os', 'debugging_messages')
