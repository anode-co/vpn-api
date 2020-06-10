from django.urls import path
from .views_api_0_1 import (
    VpnClientEventRestApiModelViewSet,
)

app_name = 'vpn_api_0_3_logging'

urlpatterns = [
    path('clients/events/', VpnClientEventRestApiModelViewSet.as_view({'post': 'add_loggable_event'}), name="Loggable Events"),
]
