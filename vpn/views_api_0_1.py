import json
from rest_framework.viewsets import ModelViewSet
from rest_framework.generics import GenericAPIView
from rest_framework.decorators import action, permission_classes
from rest_framework.response import Response
from rest_framework.pagination import LimitOffsetPagination
from rest_framework import status
from ipaddress import ip_address
from django.http import Http404
from django.shortcuts import get_object_or_404
from .models import (
    ClientSoftwareVersion,
    CjdnsVpnServer,
)
from .serializers_0_1 import (
    VpnClientEventSerializer,
    ClientSoftwareVersionSerializer,
    CjdnsVPNServerSerializer,
    VpnServerResponseSerializer,
)
from drf_yasg.utils import swagger_auto_schema
from common.permissions import (
    CsrfExemptMixin,
    HasHttpCjdnsAuthorization,
    HttpCjdnsAuthorizationRequiredMixin,
)


class PermissionsPerMethodMixin(object):
    """Give permissions per method."""

    def get_permissions(self):
        """Allows overriding default permissions with @permission_classes."""
        view = getattr(self, self.action)
        if hasattr(view, 'permission_classes'):
            return [permission_class() for permission_class in view.permission_classes]
        return super().get_permissions()


class VpnClientEventRestApiModelViewSet(CsrfExemptMixin, ModelViewSet):
    """VPN Client Events."""

    serializer_class = VpnClientEventSerializer
    pagination_class = None

    def get_client_ip(self, request):
        """Get the client IP address."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

    def get_queryset(self):
        """Override the queryset."""
        return None

    @swagger_auto_schema(responses={400: 'Invalid request'})
    def add_loggable_event(self, request):
        """Log debugging information.

        Save an event that happened on a VPN API client such as crashes or
        routing problems.
        """
        ip = None
        try:
            ip = ip_address(self.get_client_ip(request))
            if ip.version == 4:
                request.data['ip4_address'] = str(ip)
            else:
                request.data['ip6_address'] = str(ip)
        except ValueError:
            pass
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            response = {
                'status': 'success',
                'detail': 'event logged',
            }
            return Response(response)


class ClientSoftwareVersionRestApiView(GenericAPIView):
    """Client Software Version."""

    queryset = ClientSoftwareVersion.objects.filter(is_active=True)
    serializer_class = ClientSoftwareVersionSerializer

    @swagger_auto_schema(responses={404: 'client_os not found'})
    def get(self, request, client_os, client_cpu_architecture=None):
        """Get the latest client OS version data.

        Get information about the latest client app version for an OS.
        """
        if client_cpu_architecture is None or client_cpu_architecture == 'all':
            software_version = self.get_queryset().filter(client_os=client_os).order_by('-major_number', '-minor_number', '-revision_number').first()
        else:
            software_version = self.get_queryset().filter(client_os=client_os, client_cpu_architecture=client_cpu_architecture).order_by('-major_number', '-minor_number', 'revision_number').first()
        if software_version is None:
            raise Http404
        serializer = self.get_serializer(software_version)
        return Response(serializer.data)

    @action(detail=False, methods=['post'])
    @swagger_auto_schema(responses={400: 'Invalid request'})
    @permission_classes((HasHttpCjdnsAuthorization,))
    def post(self, request, client_os):
        """Register a new clent software version.

        Register a new software version when one is published.
        """
        # TODO: Require crypto auth
        request.data['client_os'] = client_os
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        response = {
            'status': 'success',
            'detail': 'version added for {}'.format(client_os)
        }
        return Response(response, status.HTTP_201_CREATED)


class CjdnsVpnServerRestApiView(ModelViewSet):
    """Cjdns VPN Servers."""

    queryset = CjdnsVpnServer.objects.filter(is_active=True, is_approved=True)
    serializer_class = CjdnsVPNServerSerializer
    pagination_class = LimitOffsetPagination
    lookup_field = 'public_key'

    @swagger_auto_schema(responses={400: 'Invalid request'})
    @permission_classes((HasHttpCjdnsAuthorization,))
    def create(self, request):
        """Add new VPN server.

        Add a new VPN server to the server list
        """
        print(json.dumps(request.data, indent=4))
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        vpn_server = serializer.save()
        vpn_server.send_new_server_email_to_admin(vpn_server)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    '''
    def list(self, request):
        """List all active VPN Servers."""
        vpn_servers = self.get_queryset()
        serializer = self.get_serializer(vpn_servers, many=True)
        return Response(serializer.data)

    @swagger_auto_schema(responses={404: 'Server public key not found'})
    def retrieve(self, request, server_public_key):
        """Retrieve a Cjdns VPN Server from the server's public_key."""
        vpn_server = get_object_or_404(self.get_queryset(), public_key=server_public_key)
        serializer = self.get_serializer(vpn_server)
        return Response(serializer.data)

    @swagger_auto_schema(responses={400: 'Invalid request'})
    @permission_classes((HasAPIKey,))
    def create(self, request):
        """Retrieve a Cjdns VPN Server from the server's public_key."""
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        vpn_server = serializer.save()
        vpn_server.send_new_server_email_to_admin(vpn_server)
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    '''


class CjdnsVpnServerAuthorizationRestApiView(HttpCjdnsAuthorizationRequiredMixin, GenericAPIView):
    """Authorize a Client public key."""

    queryset = CjdnsVpnServer.objects.filter(is_active=True, is_approved=True)
    serializer_class = VpnServerResponseSerializer
    AUTHORIZATION_URL_TIMEOUT_S = 3

    @swagger_auto_schema(responses={404: 'Server public key not found', 401: 'Authorization denied'})
    def get(self, request, public_key):
        """Authorize client on a VPN.

        Request that a VPN authorize and create routes for a client public key.
        The client that signed the HTTP request will be the one authorized.
        """
        vpn_server = get_object_or_404(self.get_queryset(), public_key=public_key)
        response_status = status.HTTP_400_BAD_REQUEST
        response = {
            'status': '',
            'message': ''
        }
        try:
            request_response = vpn_server.get_api_request_authorization(self.auth_verified_cjdns_public_key)
            print(request_response)
            print(request_response.text)
            print(request_response.json())
            try:
                json_response = request_response.json()
                json_response['expires_at'] = json_response['expiresAt']
                response_status = request_response.status_code
                response = json_response
            except json.decoder.JSONDecodeError:
                response_status = status.HTTP_400_BAD_REQUEST
                response['status'] = 'error'
                response['message'] = 'Invalid request'
        except Exception:
            response_status = status.HTTP_408_REQUEST_TIMEOUT
            response['status'] = 'error'
            response['message'] = 'VPN server timed out.'
        serializer = self.get_serializer(data=response)
        serializer.is_valid()
        return Response(serializer.data, status=response_status)


'''
class CjdnsVpnServerRestApiView(ListModelMixin, ViewSet):
    """Cjdns VPN Servers."""

    def list(self, request):
        """List all active VPN Servers."""
        vpn_servers = CjdnsVpnServer.objects.filter(is_active=True, is_approved=True)
        vpn_server_lookup = dict([(vpn_server.pk, vpn_server) for vpn_server in vpn_servers])

        network_exit_ranges_qs = NetworkExitRange.objects.select_related('cjdns_vpn_network_settings').filter(cjdns_vpn_network_settings__cjdns_vpn_server__in=vpn_servers)
        for network_exit_range in network_exit_ranges_qs:
            vpn_server = vpn_server_lookup[network_exit_range.cjdns_vpn_network_settings.cjdns_vpn_server_id]
            if vpn_server._network_settings is None:
                vpn_server._network_settings = network_exit_range.cjdns_vpn_network_settings
                vpn_server._network_settings._nat_exit_ranges = []
                vpn_server._network_settings._client_allocation_ranges = []
            if network_exit_range.type == NetworkExitRange.TYPE_NAT_EXIT:
                vpn_server._network_settings._nat_exit_ranges.append(network_exit_range)
            elif network_exit_range.type == NetworkExitRange.TYPE_CLIENT_ALLOCATION:
                vpn_server._network_settings._client_allocation_ranges.append(network_exit_range)

        peering_lines_qs = CjdnsVpnServerPeeringLine.objects.filter(cjdns_vpn_server__in=vpn_servers)
        for peering_line in peering_lines_qs:
            if vpn_server_lookup[peering_line.cjdns_vpn_server_id]._peering_lines is None:
                vpn_server_lookup[peering_line.cjdns_vpn_server_id]._peering_lines = []
            vpn_server_lookup[peering_line.cjdns_vpn_server_id]._peering_lines.append(peering_line)

        paginator = LimitOffsetPagination()
        page = paginator.paginate_queryset(vpn_servers, request)
        if page is not None:
            serialized_vpn_servers = CjdnsVPNServerSerializer(page, many=True)
            return paginator.get_paginated_response(serialized_vpn_servers.data)
        else:
            serializer = CjdnsVPNServerSerializer(vpn_servers, many=True)
            return serializer(serializer.data)

    def list_servers(self, request):
        """List all active VPN Servers."""
        return self.list(request)

    def inspect_server(self, request, server_public_key):
        """Retrieve a Cjdns VPN Server from the server's public_key."""
        # TODO: Paginate
        vpn_server = get_object_or_404(CjdnsVpnServer, is_active=True, is_approved=True, public_key=server_public_key)
        serializer = CjdnsVPNServerSerializer(vpn_server)
        return Response(serializer.data)

    def request_client_authorization(self, request, server_public_key, client_public_key):
        """Request a cjdns VPN server to authorize a client public key."""
        vpn_server = get_object_or_404(CjdnsVpnServer, is_active=True, is_approved=True, public_key=server_public_key)
        # TODO: run a connect to an API on the VPN server to authorize the client public key
        response = {
            'status': 'success',
            'detail': 'public_key "{}" has been authorized.'.format(client_public_key)
        }
        return Response(response)

    @action(detail=False, methods=['post'])
    @permission_classes((HasAPIKey,))
    def add_server(self, request):
        """Retrieve a Cjdns VPN Server from the server's public_key."""
        # TODO: require API Key
        serializer = CjdnsVPNServerSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        vpn_server = serializer.save()
        vpn_server.send_new_server_email_to_admin(vpn_server)
        return Response(serializer.data, status=status.HTTP_201_CREATED)
'''
