from django.urls import path
from .views_api_0_3 import (
    GetCoordinatorPublicKeyApiView,
)

app_name = 'common_api_0_3_coordinator'

urlpatterns = [
    path('coordinator/publickey/', GetCoordinatorPublicKeyApiView.as_view(), name="coordinator_public_key"),
]
