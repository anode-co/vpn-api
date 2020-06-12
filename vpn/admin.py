from django.contrib import admin
from .models import (
    VpnClientEvent,
    CjdnsVpnServer,
    ClientSoftwareVersion,
    CjdnsVpnServerPeeringLine,
    CjdnsVpnNetworkSettings,
    NetworkExitRange,
)


@admin.register(VpnClientEvent)
class VpnClientEventAdmin(admin.ModelAdmin):
    """Admin represtation of VpnClientEvent."""

    list_display = ('error', 'created_at', 'client_os', 'public_key')
    ordering = ('-created_at', 'error', 'public_key', 'client_os')
    list_filter = ('error', 'client_os', 'client_software_version')
    search_fields = ('error', 'public_key', 'client_os', 'debugging_messages')


class CjdnsVpnServerPeeringLineAdminInline(admin.TabularInline):
    """Inline Peering Lines."""

    model = CjdnsVpnServerPeeringLine

    fields = ('name', 'login', 'password')


class CjdnsVpnNetworkSettingsAdminInline(admin.TabularInline):
    """Inline Peering Lines."""

    model = CjdnsVpnNetworkSettings

    fields = ('uses_nat', 'per_client_allocation_size')


class NetworkExitRangeAdminInline(admin.TabularInline):
    """Inline Peering Lines."""

    model = NetworkExitRange

    fields = ('type', 'min', 'max')


class CjdnsVpnServerAdmin(admin.ModelAdmin):
    """Admin represtation of CjdnsVpnServer."""

    list_display = ('name', 'public_key', 'is_approved', 'is_active', 'is_fake', 'online_since_datetime', 'last_seen_datetime')
    ordering = ('is_fake', 'is_active', 'is_approved', 'last_seen_datetime', 'online_since_datetime', 'name', 'public_key')
    list_filter = ('is_fake', 'is_active', 'is_approved', 'online_since_datetime', 'last_seen_datetime')
    search_fields = ('public_key', 'name')
    actions = ['approve_vpns', ]
    inlines = [CjdnsVpnServerPeeringLineAdminInline, CjdnsVpnNetworkSettingsAdminInline]

    def approve_vpns(self, request, queryset):
        """Approve selected vpns."""
        count = queryset.update(is_approved=True)
        self.message_user(request, '{} vpns approved.'.format(count))
    approve_vpns.short_description = "Approve VPNs"


admin.site.register(CjdnsVpnServer, CjdnsVpnServerAdmin)


@admin.register(CjdnsVpnNetworkSettings)
class CjdnsVpnNetworkSettingsAdmin(admin.ModelAdmin):
    """Admin represtation of VpnClientEvent."""

    list_display = ('cjdns_vpn_server', 'uses_nat', 'per_client_allocation_size')
    ordering = ('cjdns_vpn_server', 'uses_nat', 'per_client_allocation_size')
    list_filter = ('cjdns_vpn_server', 'uses_nat')
    search_fields = ('cjdns_vpn_server', 'per_client_allocation_size')

    inlines = [NetworkExitRangeAdminInline, ]


@admin.register(ClientSoftwareVersion)
class ClientSoftwareVersionAdmin(admin.ModelAdmin):
    """Admin represtation of ClientSoftwareVersion."""

    list_display = ('name', 'slug', 'client_os', 'client_cpu_architecture', 'major_number', 'minor_number', 'revision_number', 'is_active',)
    ordering = ('major_number', 'minor_number', 'revision_number', 'is_active', 'client_os', 'client_cpu_architecture', 'name', 'slug', )
    search_fields = ('name', 'slug', 'client_os', 'client_cpu_architecture', 'major_number', 'minor_number', 'revision_number', 'is_active',)
    list_filter = ('client_os', 'client_cpu_architecture', 'major_number', 'minor_number', 'is_active', 'release_datetime')
