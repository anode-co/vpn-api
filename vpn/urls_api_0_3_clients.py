from django.urls import path
from .views_api_0_1 import (
    ClientSoftwareVersionRestApiView,
    ClientIpAddress,
)

app_name = 'vpn_api_0_3_clients'

urlpatterns = [
    path('clients/versions/<client_os>/<client_cpu_architecture>/', ClientSoftwareVersionRestApiView.as_view(), name="Client Software Version"),
    path('clients/versions/<client_os>/', ClientSoftwareVersionRestApiView.as_view(), name="Client Software Version"),
    path('clients/ipaddress/', ClientIpAddress.as_view(), name="client_ip"),
]
