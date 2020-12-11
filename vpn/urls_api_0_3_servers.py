from django.urls import path
from .views_api_0_1 import (
    CjdnsVpnServerRestApiView,
    CjdnsVpnServerAuthorizationRestApiView,
    CjdnsVpnServerRateRestApiView,
    CjdnsVpnServerFavoriteRestApiView,
    BulkCjdnsVpnServerRateRestApiView,
)

app_name = 'vpn_api_0_3_servers'

urlpatterns = [
    path('servers/', CjdnsVpnServerRestApiView.as_view({'get': 'list', 'post': 'create'})),
    path('servers/ratings/', BulkCjdnsVpnServerRateRestApiView.as_view()),

    path('servers/<public_key>/', CjdnsVpnServerRestApiView.as_view({'get': 'retrieve', 'put': 'update'})),
    path('servers/<public_key>/authorize/', CjdnsVpnServerAuthorizationRestApiView.as_view()),

    path('servers/<public_key>/rating/', CjdnsVpnServerRateRestApiView.as_view()),
    path('servers/<public_key>/favorite/', CjdnsVpnServerFavoriteRestApiView.as_view()),

]
