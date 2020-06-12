from django.urls import path
from .views_api_0_1 import (
    CjdnsVpnServerRestApiView,
    CjdnsVpnServerAuthorizationRestApiView,
)

app_name = 'vpn_api_0_3_servers'

urlpatterns = [
    path('servers/', CjdnsVpnServerRestApiView.as_view({'get': 'list', 'post': 'create'})),
    path('servers/<public_key>/', CjdnsVpnServerRestApiView.as_view({'get': 'retrieve'})),
    path('servers/<public_key>/authorize/', CjdnsVpnServerAuthorizationRestApiView.as_view()),
]
