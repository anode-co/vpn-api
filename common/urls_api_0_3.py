from django.urls import path
from .views_api_0_3 import (
    CreateAccountApiView,
    CreateResetPasswordRequestApiView,
    ResetPasswordConfirmationStatusApiView,
    DigestTestApiView,
    AuthTestApiView,
    RegisterPublicKeyView,
)

app_name = 'common_api_0_3'

urlpatterns = [
    path('vpn/accounts/', CreateAccountApiView.as_view(), name="Register New Client Account"),
    path('vpn/accounts/<client_email>/password/', CreateResetPasswordRequestApiView.as_view(), name="Request to change the password of an existing client account"),
    path('vpn/accounts/<client_email>/password/<password_reset_token>/', ResetPasswordConfirmationStatusApiView.as_view(), name="check_password_reset_confirmation"),
    path('vpn/clients/publickeys/', RegisterPublicKeyView.as_view(), name="register_client_public_key"),
    path('tests/digest/', DigestTestApiView.as_view(), name="digest_test"),
    path('tests/auth/', AuthTestApiView.as_view(), name="auth_test"),
]
