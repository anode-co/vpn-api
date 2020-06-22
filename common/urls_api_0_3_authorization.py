from django.urls import path
from .views_api_0_3 import (
    AuthTestApiView,
    RegisterPublicKeyView,
)

app_name = 'common_api_0_3_authorization'

urlpatterns = [
    path('tests/auth/', AuthTestApiView.as_view(), name="test_auth"),
    path('vpn/clients/publickeys/', RegisterPublicKeyView.as_view(), name="register_client_public_key"),
]
