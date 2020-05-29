from django.urls import path
from .views_api_0_1 import (
    VpnClientEventRestApiModelViewSet,
    ClientSoftwareVersionRestApiView,
    CjdnsVpnServerRestApiView,
    CjdnsVpnServerAuthorizationRestApiView,
)

app_name = 'vpn_api_0_3'

urlpatterns = [
    path('clients/events/', VpnClientEventRestApiModelViewSet.as_view({'post': 'add_loggable_event'}), name="Loggable Events"),
    path('clients/versions/<client_os>/', ClientSoftwareVersionRestApiView.as_view(), name="Client Software Version"),
    path('servers/', CjdnsVpnServerRestApiView.as_view({'get': 'list', 'post': 'create'})),
    path('servers/<server_public_key>/', CjdnsVpnServerRestApiView.as_view({'get': 'retrieve'})),
    path('servers/<server_public_key>/authorize/<client_public_key>/', CjdnsVpnServerAuthorizationRestApiView.as_view()),
]
