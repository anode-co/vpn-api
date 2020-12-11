import json
import os

from .models import (
    ClientSoftwareVersion,
    CjdnsVpnServer,
    VpnClientEvent,
    MattermostChatApi,
    UserCjdnsVpnServerFavorite,
    NetworkExitRange,
    CjdnsVpnNetworkSettings,
    UserCjdnsVpnServerRating,
)
from .serializers_0_1 import (
    VpnClientEventSerializer,
    ClientSoftwareVersionSerializer,
    CjdnsVPNServerSerializer,
    VpnServerAuthorizationRequestSerializer,
    VpnServerResponseSerializer,
    VpnRateServerSerializer,
    VpnServerRatingSerializer,
    VpnRateServerResponseSerializer,
    VpnFavoriteServerSerializer,
)
from common.models import (
    User,
)
from common.permissions import (
    CsrfExemptMixin,
    HasHttpCjdnsAuthorization,
    HttpCjdnsAuthorizationRequiredMixin,
    HttpCjdnsAuthorizationVerifier,
)
from common.serializers_0_3 import GenericResponseSerializer
from django.conf import settings
from django.http import Http404
from django.shortcuts import get_object_or_404
from django.urls import reverse
from django.utils import timezone
from drf_yasg.utils import swagger_auto_schema
from ipaddress import ip_address
import ipaddress
from rest_framework import status
from rest_framework.generics import GenericAPIView
from rest_framework.pagination import LimitOffsetPagination
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.viewsets import ModelViewSet
# from rest_framework_api_key.permissions import HasAPIKey
from rest_framework_bulk import (
    ListBulkCreateAPIView,
    ListBulkCreateUpdateAPIView,
)


# from django.core.mail import send_mail

def method_permission_classes(classes):
    """Custom method decorator to allow for per-method permissions."""
    def decorator(func):
        """Create a method decorater."""
        def decorated_func(self, *args, **kwargs):
            """Apply the decorator function."""
            print(self.request)
            print(self.request.headers)
            self.permission_classes = classes
            print("permission classes")
            print(classes)
            # this call is needed for request permissions
            self.check_permissions(self.request)
            result = func(self, *args, **kwargs)
            print("result")
            print(result)
            return result
        return decorated_func
    return decorator


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

    def get_loggable_event(self, request):
        """GET."""
        event = VpnClientEvent.objects.last()
        serializer = VpnClientEventSerializer(event)
        return Response(serializer.data)

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
        log_type = 'error'
        serializer = self.get_serializer(data=request.data)
        # serializer.is_valid(raise_exception=True)
        # invalid request but logged anyway
        if serializer.is_valid() is False:
            log_type = 'unparsable error'
            client_event = VpnClientEvent()
            if 'public_key' in request.data:
                client_event.public_key = request.data['public_key']
            if 'error' in request.data:
                client_event.error = request.data['error']
            if 'client_software_version' in request.data:
                client_event.client_software_version = request.data['client_software_version']
            if 'client_os' in request.data:
                client_event.client_os = request.data['client_os']
            if 'client_os_version' in request.data:
                client_event.client_os_version = request.data['client_os_version']
            if 'cpu_utilization_percent' in request.data:
                client_event.cpu_utilization_percent = request.data['cpu_utilization_percent']
            if 'available_memory_bytes' in request.data:
                client_event.available_memory_bytes = request.data['available_memory_bytes']
            if 'local_timestamp' in request.data:
                client_event.local_timestamp = request.data['local_timestamp']
            if 'ip4_address' in request.data:
                client_event.ip4_address = request.data['ip4_address']
            if 'ip6_address' in request.data:
                client_event.ip6_address = request.data['ip6_address']
            if 'message' in request.data:
                client_event.message = request.data['message']
            if 'previous_android_log' in request.data:
                client_event.previous_android_log = request.data['previous_android_log']
            if 'new_android_log' in request.data:
                client_event.new_android_log = request.data['new_android_log']
            client_event.debugging_messages = json.dumps(request.data, indent=4)
            client_event.save()
            response = {
                'status': 'success',
                'detail': 'event logged',
                'errors': serializer.errors,
            }
        else:
            client_event = serializer.save()
            response = {
                'status': 'success',
                'detail': 'event logged',
            }

        if client_event.error != VpnClientEvent.ERROR_APP_USAGE:
            mattermost_text = "App client {}: {}\npubkey: {}, username: {}".format(
                log_type,
                request.build_absolute_uri(reverse(
                    'admin:{}_{}_change'.format(client_event._meta.app_label, client_event._meta.model_name),
                    args=(client_event.pk, )
                )),
                client_event.public_key,
                client_event.username
            )
            mattermost = MattermostChatApi(settings.MATTERMOST_HOST, settings.MATTERMOST_ENDPOINT)
            mattermost.send_message(mattermost_text)
            # Output to text:
            output_filename = os.path.join(settings.BASE_DIR, 'buggy_log_input.txt')
            outputs = [
                '=================================',
                'New error: {}'.format(request.build_absolute_uri(reverse(
                    'admin:{}_{}_change'.format(client_event._meta.app_label, client_event._meta.model_name),
                    args=(client_event.pk, )
                ))),
                'Datetime: {}'.format(timezone.now().strftime('%Y-%m-%d %H:%I:%S')),
                'Input: ',
                json.dumps(request.data, indent=3)
            ]
            output = "\n".join(outputs)
            with open(output_filename, 'a') as f:
                f.write(output)
            '''
            send_mail(
                'New VPN App error log',
                output,
                settings.DEFAULT_FROM_EMAIL,
                [
                    'adonis@anode.co',
                    'cjd@anode.co',
                    'dimitris@commonslab.gr '
                ],
                fail_silently=False
            )
            '''
        return Response(response)


class BulkVpnClientEventRestApiModelViewSet(ListBulkCreateAPIView):
    """Bulk VPN Client Event."""

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
        str_ip = ''
        try:
            ip = ip_address(self.get_client_ip(request))
            str_ip = str(ip)
        except ValueError:
            pass

        data = request.data
        for item in data:
            if ip.version == 4:
                item['ip4_address'] = str_ip
            else:
                item['ip6_address'] = str_ip

        serializer = self.get_serializer(data=data)

        log_type = 'error'
        # serializer.is_valid(raise_exception=True)
        # invalid request but logged anyway
        response = {}
        if serializer.is_valid() is False:
            for item in data:
                log_type = 'unparsable error'
                client_event = VpnClientEvent()
                if 'public_key' in item:
                    client_event.public_key = item['public_key']
                if 'error' in item:
                    client_event.error = item['error']
                if 'client_software_version' in item:
                    client_event.client_software_version = item['client_software_version']
                if 'client_os' in item:
                    client_event.client_os = item['client_os']
                if 'client_os_version' in item:
                    client_event.client_os_version = item['client_os_version']
                if 'cpu_utilization_percent' in item:
                    client_event.cpu_utilization_percent = item['cpu_utilization_percent']
                if 'available_memory_bytes' in item:
                    client_event.available_memory_bytes = item['available_memory_bytes']
                if 'local_timestamp' in item:
                    client_event.local_timestamp = item['local_timestamp']
                if 'ip4_address' in item:
                    client_event.ip4_address = item['ip4_address']
                if 'ip6_address' in item:
                    client_event.ip6_address = item['ip6_address']
                if 'message' in item:
                    client_event.message = item['message']
                if 'previous_android_log' in item:
                    client_event.previous_android_log = item['previous_android_log']
                if 'new_android_log' in item:
                    client_event.new_android_log = item['new_android_log']
                client_event.debugging_messages = json.dumps(item, indent=4)
                client_event.save()
            response = {
                'status': 'success',
                'detail': 'event logged',
                'errors': serializer.errors,
            }
        else:
            client_events = serializer.create(serializer.validated_data)
            response = {
                'status': 'success',
                'detail': 'event logged',
            }

        counter = 0
        for client_event in client_events:
            if client_event.error != VpnClientEvent.ERROR_APP_USAGE:
                mattermost_text = "App client {}: {}\npubkey: {}, username: {}".format(
                    log_type,
                    request.build_absolute_uri(reverse(
                        'admin:{}_{}_change'.format(client_event._meta.app_label, client_event._meta.model_name),
                        args=(client_event.pk, )
                    )),
                    client_event.public_key,
                    client_event.username
                )
                mattermost = MattermostChatApi(settings.MATTERMOST_HOST, settings.MATTERMOST_ENDPOINT)
                mattermost.send_message(mattermost_text)
                # Output to text:
                output_filename = os.path.join(settings.BASE_DIR, 'buggy_log_input.txt')
                outputs = [
                    '=================================',
                    'New error: {}'.format(request.build_absolute_uri(reverse(
                        'admin:{}_{}_change'.format(client_event._meta.app_label, client_event._meta.model_name),
                        args=(client_event.pk, )
                    ))),
                    'Datetime: {}'.format(timezone.now().strftime('%Y-%m-%d %H:%I:%S')),
                    'Input: ',
                    json.dumps(data[counter], indent=3)
                ]
                output = "\n".join(outputs)
                with open(output_filename, 'a') as f:
                    f.write(output)
                '''
                send_mail(
                    'New VPN App error log',
                    output,
                    settings.DEFAULT_FROM_EMAIL,
                    [
                        'adonis@anode.co',
                        'cjd@anode.co',
                        'dimitris@commonslab.gr '
                    ],
                    fail_silently=False
                )
                '''
                counter += 1
        return Response(response)


class ClientSoftwareVersionRestApiView(GenericAPIView):
    """Client Software Version."""

    queryset = ClientSoftwareVersion.objects.filter(is_active=True)
    serializer_class = ClientSoftwareVersionSerializer
    permission_classes = [AllowAny]

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

    @swagger_auto_schema(responses={400: 'Invalid request', 201: GenericResponseSerializer})
    #@method_permission_classes((HasAPIKey,))
    def post(self, request, client_os):
        """Register a new clent software version.

        Register a new software version when one is published.
        """
        # TODO: Require crypto auth
        request.data['client_os'] = client_os
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        output = {
            'status': 'success',
            'detail': 'version added for {}'.format(client_os)
        }
        serializer = GenericResponseSerializer(data=output)
        serializer.is_valid()
        return Response(serializer.data, status.HTTP_201_CREATED)


class CjdnsVpnServerRestApiView(ModelViewSet):
    """Cjdns VPN Servers."""

    queryset = CjdnsVpnServer.objects.select_related().filter(is_active=True, is_approved=True, is_fake=False)
    serializer_class = CjdnsVPNServerSerializer
    pagination_class = LimitOffsetPagination
    lookup_field = 'public_key'

    @swagger_auto_schema(responses={400: 'Invalid request'})
    @method_permission_classes((HasHttpCjdnsAuthorization,))
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

    @swagger_auto_schema(responses={200: GenericResponseSerializer, 400: 'Invalid request'})
    @method_permission_classes((HasHttpCjdnsAuthorization,))
    def update(self, request, public_key):
        """Update a VPN server.

        Update last-seen time
        """
        digest_verifier = HttpCjdnsAuthorizationVerifier(request)
        digest_verifier.is_valid(raise_exception=False)
        serializer = VpnServerAuthorizationRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            vpn_server = self.get_queryset().get(public_key=digest_verifier.public_key)
        except CjdnsVpnServer.DoesNotExist:
            raise Http404
        vpn_server.save()
        output = {
            'status': 'success',
        }
        output_serializer = GenericResponseSerializer(data=output)
        output_serializer.is_valid()
        return Response(output_serializer.data)

    @swagger_auto_schema(responses={400: 'Invalid request'})
    def list(self, request):
        """List all active VPN Servers."""
        digest_verifier = HttpCjdnsAuthorizationVerifier(request)
        digest_verifies = digest_verifier.is_valid(raise_exception=False)
        vpn_servers = self.get_queryset()
        network_settings = CjdnsVpnNetworkSettings.objects.filter(cjdns_vpn_server__in=vpn_servers)
        # peering_lines = CjdnsVpnServerPeeringLine.objects.filter(cjdns_vpn_server__in=vpn_servers)
        exit_ranges = NetworkExitRange.objects.filter(cjdns_vpn_network_settings__in=network_settings)

        vpn_server_lookup = {}
        for vpn_server in vpn_servers:
            vpn_server_lookup[vpn_server.pk] = vpn_server
            vpn_server._peering_lines = []
            vpn_server._network_settings = None
        network_settings_lookup = {}
        for network_setting in network_settings:
            network_settings_lookup[network_setting.pk] = network_setting
            network_setting._nat_exit_ranges = []
            network_setting._client_allocation_ranges = []
            vpn_server_lookup[network_setting.cjdns_vpn_server_id]._network_settings = network_setting
        for exit_range in exit_ranges:
            if exit_range.type == NetworkExitRange.TYPE_NAT_EXIT:
                network_settings_lookup[exit_range.cjdns_vpn_network_settings_id]._nat_exit_ranges.append(exit_range)
            elif exit_range.type == NetworkExitRange.TYPE_CLIENT_ALLOCATION:
                network_settings_lookup[exit_range.cjdns_vpn_network_settings_id]._client_allocation_ranges.append(exit_range)

        '''
        for peering_line in peering_lines:
            vpn_server_lookup[network_setting.cjdns_vpn_server_id].peering_lines.append(peering_line)
        '''

        if digest_verifies is True:
            favorites = UserCjdnsVpnServerFavorite.objects.filter(user__public_key=digest_verifier.public_key, cjdns_vpn_server__in=vpn_servers)
            if len(favorites) > 0:
                favorite_lookup = dict([(f.cjdns_vpn_server_id, f) for f in favorites])
                for vpn_server in vpn_servers:
                    favorite = favorite_lookup.get(vpn_server.pk)
                    if favorite is None:
                        vpn_server.is_favorite = True
                    else:
                        vpn_server.is_favorite = False

        serializer = self.get_serializer(vpn_servers, many=True)
        return Response(serializer.data)

    @swagger_auto_schema(responses={404: 'Server public key not found'})
    def retrieve(self, request, public_key):
        """Retrieve a Cjdns VPN Server from the server's public_key."""
        digest_verifier = HttpCjdnsAuthorizationVerifier(request)
        digest_verifies = digest_verifier.is_valid(raise_exception=False)
        try:
            vpn_server = self.get_queryset().get(public_key=public_key)
        except CjdnsVpnServer.DoesNotExist:
            raise Http404
        if digest_verifies is True:
            try:
                UserCjdnsVpnServerFavorite.objects.get(user__public_key=digest_verifier.public_key, cjdns_vpn_server=vpn_server)
                vpn_server.is_favorite = True
            except UserCjdnsVpnServerFavorite.DoesNotExist:
                vpn_server.is_favorite = False
        else:
            vpn_server.is_favorite = None
        serializer = self.get_serializer(vpn_server)
        return Response(serializer.data)

    '''
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
    serializer_class = VpnServerAuthorizationRequestSerializer
    AUTHORIZATION_URL_TIMEOUT_S = 3

    '''
    @swagger_auto_schema(responses={404: 'Server public key not found', 401: 'Authorization denied', 200: VpnServerResponseSerializer, 201: VpnServerResponseSerializer})
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

    def get_client_ip(self, request):
        """Get the client IP address."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

    @swagger_auto_schema(responses={404: 'Server public key not found', 401: 'Authorization denied', 200: VpnServerResponseSerializer, 201: VpnServerResponseSerializer})
    def post(self, request, public_key):
        """Authorize client on a VPN.

        Request that a VPN authorize and create routes for a client public key.
        The client that signed the HTTP request will be the one authorized.
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        vpn_server = get_object_or_404(self.get_queryset(), public_key=public_key)
        response_status = status.HTTP_400_BAD_REQUEST
        response = {
            'status': '',
            'message': ''
        }

        client_ip = self.get_client_ip(request)
        client_ip4_address = None
        client_ip6_address = None
        if client_ip is not None:
            try:
                ip = ipaddress.ip_address(client_ip)
                if ip.version == 4:
                    client_ip4_address = client_ip
                elif ip.version == 6:
                    client_ip6_address = client_ip
            except ValueError:
                pass

        do_logging = False
        logger = VpnClientEvent()
        logger.public_key = self.auth_verified_cjdns_public_key
        logger.error = "connectionFailed"
        logger.client_software_version = 'unknown'
        logger.client_os = 'unknown'
        logger.client_os_version = 'unknown'
        logger.local_timestamp = timezone.now()
        logger.ip4_address = client_ip4_address
        logger.ip6_address = client_ip6_address
        logger.previous_android_log = "server public key: {}".format(public_key)

        # self.auth_verified_cjdns_public_key = 'munw8n871pb5kw7fypv2fgj9jmplg67nr5s4mws8uj8g3uvgtf20.k'
        try:
            request_response = vpn_server.get_api_request_authorization(self.auth_verified_cjdns_public_key, serializer.validated_data['date'])
            # print(request_response)
            # print(request_response.text)
            # print(request_response.json())
            try:
                json_response = request_response.json()
                # json_response['status'] = json_response['status']
                # json_response['expires_at'] = json_response['expiresAt']
                response_status = request_response.status_code
                response = json_response
                print("SUCCESS")

                if request_response.status_code != 200 and request_response.status_code != 201:
                    logger.message = 'VPN connection error on behalf of app'
                    logger.debugging_messages = request_response.text
                    logger.previous_android_log = "server public key: {}".format(public_key)
                    do_logging = True

            except json.decoder.JSONDecodeError:
                response_status = status.HTTP_500_INTERNAL_SERVER_ERROR
                response['status'] = 'error'
                response['message'] = 'Could not decode VPN JSON response: \'{}\''.format(response.text)

                logger.message = 'VPN connection error on behalf of app'
                logger.debugging_messages = request_response.text
                logger.previous_android_log = "server public key: {}".format(public_key)
                do_logging = True

                print("JSON DECODE ERROR")
        except Exception:
            response_status = status.HTTP_408_REQUEST_TIMEOUT
            response['status'] = 'error'
            response['message'] = 'VPN server timed out.'
            print("SERVER TIMED OUT")

            logger.message = 'VPN Server timed out'
            logger.debugging_messages = "VPN Server timed out"
            logger.previous_android_log = "server public key: {}".format(public_key)
            do_logging = True

        serializer = VpnServerResponseSerializer(data=response)
        serializer.is_valid()
        print("Returning output")
        print(serializer.data)

        if do_logging is True:
            logger.save()
        return Response(serializer.data, status=response_status)


class CjdnsVpnServerRateRestApiView(HttpCjdnsAuthorizationRequiredMixin, GenericAPIView):
    """Rate a VPN Server."""

    queryset = CjdnsVpnServer.objects.filter(is_active=True, is_approved=True)
    serializer_class = VpnRateServerSerializer

    def get_object(self):
        """Get a single object by public_key."""
        public_key = self.kwargs['public_key']
        print(public_key)
        return self.get_queryset().get(public_key=public_key)

    @swagger_auto_schema(responses={404: 'Server public key not found', 401: 'Authorization denied', 200: VpnRateServerResponseSerializer})
    def get(self, request, public_key):
        """Comment here."""
        try:
            vpn_server = self.get_object()
        except UserCjdnsVpnServerRating.DoesNotExist:
            raise Http404
        server_rating_serializer = VpnServerRatingSerializer(vpn_server)
        return Response(server_rating_serializer.data)

    @swagger_auto_schema(responses={404: 'Server public key not found', 401: 'Authorization denied', 201: VpnRateServerResponseSerializer})
    def post(self, request, public_key):
        """Comment here."""
        user = User.objects.filter(public_key=self.auth_verified_cjdns_public_key).first()
        try:
            vpn_server = self.get_object()
        except CjdnsVpnServer.DoesNotExist:
            raise Http404
        data = request.data
        data['cjdns_vpn_server'] = vpn_server.id
        del data['public_key']
        serializer = self.get_serializer(data=data, user=user)  # , cjdns_vpn_server=vpn_server)
        serializer.is_valid(raise_exception=True)
        serializer.create(serializer.validated_data)
        server_rating_serializer = VpnRateServerResponseSerializer(vpn_server)
        return Response(server_rating_serializer.data, status=status.HTTP_201_CREATED)


class BulkCjdnsVpnServerRateRestApiView(HttpCjdnsAuthorizationRequiredMixin, ListBulkCreateAPIView):
    """Rate a VPN Server."""

    queryset = CjdnsVpnServer.objects.filter(is_active=True, is_approved=True)
    serializer_class = VpnRateServerSerializer

    @swagger_auto_schema(responses={404: 'Server public key not found', 401: 'Authorization denied', 201: VpnRateServerResponseSerializer})
    def post(self, request):
        """Comment here."""
        user = User.objects.filter(public_key=self.auth_verified_cjdns_public_key).first()
        data = request.data
        public_keys = []
        for row in data:
            public_keys.append(row['public_key'])
        vpn_servers = self.get_queryset().filter(public_key__in=public_keys)
        vpn_server_lookup = {}
        for vpn_server in vpn_servers:
            vpn_server_lookup[vpn_server.public_key] = vpn_server
        for row in data:
            row['cjdns_vpn_server'] = vpn_server_lookup[row['public_key']].id
            del row['public_key']
        serializer = self.get_serializer(data=data, user=user, many=True)
        serializer.is_valid(raise_exception=True)
        created_ratings = serializer.create(user, serializer.validated_data)
        server_rating_serializer = VpnRateServerResponseSerializer(data=created_ratings, many=True)
        server_rating_serializer.is_valid()
        return Response(server_rating_serializer.data, status=status.HTTP_201_CREATED)


class CjdnsVpnServerFavoriteRestApiView(HttpCjdnsAuthorizationRequiredMixin, GenericAPIView):
    """Rate a VPN Server."""

    queryset = CjdnsVpnServer.objects.filter(is_active=True, is_approved=True)
    serializer_class = None

    @swagger_auto_schema(responses={404: 'Server public key not found', 401: 'Authorization denied', 201: GenericResponseSerializer})
    def post(self, request, public_key):
        """Comment here."""
        print("poting!")
        user = User.objects.filter(public_key=self.auth_verified_cjdns_public_key).first()
        print(user)
        print(public_key)
        try:
            vpn_server = self.get_queryset().get(public_key=public_key)
        except CjdnsVpnServer.DoesNotExist:
            raise Http404
        favorite, _ = UserCjdnsVpnServerFavorite.objects.get_or_create(cjdns_vpn_server=vpn_server, user=user)
        output = {
            'status': 'success'
        }
        output_serializer = GenericResponseSerializer(data=output)
        output_serializer.is_valid()
        return Response(output_serializer.data, status=status.HTTP_201_CREATED)

    def delete(self, request, public_key):
        """Delete favorite."""
        # user = User.objects.filter(public_key=self.auth_verified_cjdns_public_key).first()
        try:
            vpn_server = self.get_queryset().get(public_key=public_key)
        except CjdnsVpnServer.DoesNotExist:
            raise Http404
        UserCjdnsVpnServerFavorite.objects.filter(user__public_key=self.auth_verified_cjdns_public_key, cjdns_vpn_server=vpn_server).delete()
        output = {
            'status': 'success'
        }
        output_serializer = GenericResponseSerializer(data=output)
        output_serializer.is_valid()
        return Response(output_serializer.data)


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
