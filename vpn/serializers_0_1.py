import json
from rest_framework import serializers
from rest_framework_friendly_errors.mixins import FriendlyErrorMessagesMixin
from .models import (
    VpnClientEvent,
    ClientSoftwareVersion,
    CjdnsVpnServer,
    CjdnsVpnServerPeeringLine,
    CjdnsVpnNetworkSettings,
    NetworkExitRange
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
            'cpu_utilization_percent',
            'available_memory_bytes',
            'local_timestamp',
            'ip4_address',
            'ip6_address',
            'message',
            'previous_android_log',
            'new_android_log',
            'debugging_messages',
        ]


class ClientSoftwareVersionSerializer(serializers.ModelSerializer):
    """Serialize a ClientSoftwareVersion."""

    class Meta:
        """Meta."""

        model = ClientSoftwareVersion
        fields = [
            'client_os',
            'client_software_version',
            'major_number',
            'minor_number',
            'revision_number',
            'binary_download_url',
            'certificate_url',
            'release_datetime'
        ]


class NetworkExitRangeSerialier(serializers.ModelSerializer):
    """Serialize a NetworkExitRange."""

    class Meta:
        """Meta information for the serializer."""

        model = NetworkExitRange
        fields = [
            'min',
            'max'
        ]


class CjdnsVpnServerPeeringLineSerializer(serializers.ModelSerializer):
    """Serialize a CjdnsVpnServerPeeringLine."""

    class Meta:
        """Meta information for the serializer."""

        model = CjdnsVpnServerPeeringLine
        fields = [
            'name',
            'login',
            'password'
        ]


class CjdnsVpnNetworkSettingsSerializer(serializers.ModelSerializer):
    """Serializer a CjdnsVpnNetworkSettings."""

    nat_exit_ranges = NetworkExitRangeSerialier(many=True)
    client_allocation_ranges = NetworkExitRangeSerialier(many=True)

    class Meta:
        """Meta information for the serializer."""

        model = CjdnsVpnNetworkSettings
        fields = [
            'uses_nat',
            'per_client_allocation_size',
            'nat_exit_ranges',
            'client_allocation_ranges'
        ]


class CjdnsVPNServerSerializer(serializers.ModelSerializer):
    """Serialize a CjdnsVpnServer."""

    network_settings = CjdnsVpnNetworkSettingsSerializer()
    peering_lines = CjdnsVpnServerPeeringLineSerializer(many=True)

    class Meta:
        """Meta information for the serializer."""

        model = CjdnsVpnServer
        fields = [
            'name',
            'public_key',
            'bandwidth_bps',
            'network_settings',
            'peering_lines',
            'online_since_datetime',
            'last_seen_datetime'
        ]

    def create(self, validated_data):
        """Create a new cjdns VPN Server."""
        print(json.dumps(validated_data, indent=4))
        peering_lines_data = validated_data.pop('peering_lines')
        network_settings_data = validated_data.pop('network_settings')

        vpn_server = CjdnsVpnServer.objects.create(**validated_data)

        peering_lines = []
        for peering_line_data in peering_lines_data:
            peering_line_data['cjdns_vpn_server'] = vpn_server
            peering_line = CjdnsVpnServerPeeringLine(**peering_line_data)
            peering_lines.append(peering_line)
        CjdnsVpnServerPeeringLine.objects.bulk_create(peering_lines)
        vpn_server._peering_lines = peering_lines

        nat_exit_ranges_data = network_settings_data.pop('nat_exit_ranges')
        allocation_ranges_data = network_settings_data.pop('client_allocation_ranges')
        network_settings_data['cjdns_vpn_server'] = vpn_server
        network_settings = CjdnsVpnNetworkSettings.objects.create(**network_settings_data)

        nat_exit_ranges = []
        for nat_exit_range_data in nat_exit_ranges_data:
            nat_exit_range_data['cjdns_vpn_network_settings'] = network_settings
            nat_exit_range_data['type'] = NetworkExitRange.TYPE_NAT_EXIT
            nat_exit_range = NetworkExitRange(**nat_exit_range_data)
            nat_exit_ranges.append(nat_exit_range)
        NetworkExitRange.objects.bulk_create(nat_exit_ranges)
        network_settings._nat_exit_ranges = nat_exit_ranges

        allocation_ranges = []
        for allocation_range_data in allocation_ranges_data:
            allocation_range_data['cjdns_vpn_network_settings'] = network_settings
            allocation_range_data['type'] = NetworkExitRange.TYPE_CLIENT_ALLOCATION
            allocation_range = NetworkExitRange(**allocation_range_data)
            allocation_ranges.append(allocation_range)
        NetworkExitRange.objects.bulk_create(allocation_ranges)
        network_settings._allocation_ranges = allocation_ranges

        vpn_server._network_settings = network_settings

        return vpn_server
