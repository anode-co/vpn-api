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


class VpnServerResponseSerializer(serializers.Serializer):
    """Serialize the VPN Server response."""

    status = serializers.CharField()
    message = serializers.CharField(allow_null=True)
    expires_at = serializers.IntegerField(allow_null=True)


class VpnServerAuthorizationRequestSerializer(serializers.Serializer):
    """Serialize the VPN Server response."""

    date = serializers.IntegerField()


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
        example = {
            'public_key': 'lbqr0rzyc2tuysw3w8gfr95u68kujzlq7zht5hyf452u8yshr120.k',
            'error': 'connection_failed',
            'client_software_version': 'android-anode-0.9.11a',
            'client_os': 'Android',
            'client_os_version': '9.1',
            'cpu_utilization_percent': 34,
            'available_memory_bytes': 340243234,
            'local_timestamp': '2017-07-21T17:32:28Z',
            'ip4_address': '91.207.175.41',
            'ip6_address': 'fc29:c42b:fa32:b411:71c7:cf70:98c6:9427',
            'message': 'cjdns route failed unexpectedly',
            'previous_android_log': '1588074618 INFO RandomSeed.c:42 Attempting...',
            'new_android_log': '1588074618 INFO RandomSeed.c:42 Attempting...',
            'debugging_messages': '1588074618 INFO RandomSeed.c:42 Attempting...',
        }


class ClientSoftwareVersionSerializer(serializers.ModelSerializer):
    """Serialize a ClientSoftwareVersion."""

    class Meta:
        """Meta."""

        model = ClientSoftwareVersion
        fields = [
            'client_os',
            'client_cpu_architecture',
            'client_software_version',
            'major_number',
            'minor_number',
            'revision_number',
            'binary_download_url',
            'file_size_bytes',
            'certificate_url',
            'release_datetime'
        ]
        example = {
            'client_os': 'android',
            'client_cpu_architecture': 'i686',
            'client_software_version': 'android-anode-0.9.11a',
            'major_number': 0,
            'minor_number': 1,
            'revision_number': '11a',
            'binary_download_url': 'https://anode.co/downloads/android-anode-0.9.11a.apk',
            'file_size_bytes': 4766924,
            'certificate_url': 'https://anode.co/downloads/certificates/android-anode-0.9.11a.pem',
            'release_datetime': '2017-07-21T17:32:28Z'
        }


class NetworkExitRangeSerialier(serializers.ModelSerializer):
    """Serialize a NetworkExitRange."""

    class Meta:
        """Meta information for the serializer."""

        model = NetworkExitRange
        fields = [
            'min',
            'max'
        ]
        example = {
            'min': '10.0.0.1',
            'max': '10.0.0.29',
        }


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
        example = {
            'name': 'Stretch Armstrong',
            'login': 'my-cjdns-username',
            'password': 'skZ6UtW5u09lHNsj6tQ51s1SPrCBkedbNf0Tp0GbMJDyR4e9T04ZZwIDAQAB.k'
        }


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
        example = {
            'uses_nat': True,
            'per_client_allocation_size': '/0',
        }


class CjdnsVPNServerSerializer(serializers.ModelSerializer):
    """Serialize a CjdnsVpnServer."""

    network_settings = CjdnsVpnNetworkSettingsSerializer()
    # peering_lines = CjdnsVpnServerPeeringLineSerializer(many=True)

    class Meta:
        """Meta information for the serializer."""

        model = CjdnsVpnServer
        fields = [
            'name',
            'public_key',
            'bandwidth_bps',
            'region',
            'country_code',
            'network_settings',
            # 'peering_lines',
            'online_since_datetime',
            'last_seen_datetime',
            'is_fake'
        ]
        example = {
            'name': 'Kenny G',
            'public_key': 'lbqr0rzyc2tuysw3w8gfr95u68kujzlq7zht5hyf452u8yshr120',
            'bandwidth_bps': 10485760,
            'online_since_datetime': "2017-07-21T17:32:28Z",
            'last_seen_datetime': "2017-07-21T17:32:28Z",
            'is_fake': False,
        }

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
