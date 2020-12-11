from django.urls import path
from .views_api_0_1 import (
    VpnClientEventRestApiModelViewSet,
    BulkVpnClientEventRestApiModelViewSet,
)

app_name = 'vpn_api_0_3_logging'

urlpatterns = [
    path('clients/events/', VpnClientEventRestApiModelViewSet.as_view({'get': 'get_loggable_event', 'post': 'add_loggable_event'}), name="Loggable Events"),
    path('clients/events/bulk/', BulkVpnClientEventRestApiModelViewSet.as_view(), name="Bulk Loggable Events"),
]
