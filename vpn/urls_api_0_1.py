from django.urls import path
from .views_api_0_1 import (
    VpnClientEventRestApiModelViewSet,
    ClientSoftwareVersionRestApiView,
    CjdnsVpnServerRestApiView
)

app_name = 'vpn_api_0_1'

urlpatterns = [
    path('clients/events/', VpnClientEventRestApiModelViewSet.as_view({'post': 'add_loggable_event'})),
    path('clients/versions/<client_os>/', ClientSoftwareVersionRestApiView.as_view({'get': 'get_latest_version', 'post': 'add_new_version'})),
    path('servers/', CjdnsVpnServerRestApiView.as_view({'get': 'list_servers', 'post': 'add_server'})),
    path('servers/<server_public_key>/', CjdnsVpnServerRestApiView.as_view({'get': 'inspect_server', })),
    path('servers/<server_public_key>/authorize/<client_public_key>/', CjdnsVpnServerRestApiView.as_view({'get': 'request_client_authorization', })),
]
