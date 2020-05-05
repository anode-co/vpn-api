from django.contrib import admin
from .models import (
    VpnClientEvent
)


@admin.register(VpnClientEvent)
class VpnClientEventAdmin(admin.ModelAdmin):
    """Admin represtation of VpnClientEvent."""

    list_display = ('error', 'client_software_version', 'client_os', 'public_key')
    ordering = ('error', 'public_key', 'client_os', 'client_software_version')
    list_filter = ('error', 'client_os', 'client_software_version')
