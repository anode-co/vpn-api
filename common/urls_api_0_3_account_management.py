from django.urls import path
from .views_api_0_3 import (
    CreateAccountApiView,
    CreateResetPasswordRequestApiView,
    CreateAccountConfirmationStatusApiView,
)

app_name = 'common_api_0_3_account_management'

urlpatterns = [
    path('vpn/accounts/', CreateAccountApiView.as_view(), name="Register New Client Account"),
    path('vpn/accounts/<client_email>/confirmstatus/', CreateAccountConfirmationStatusApiView.as_view(), name="check_account_registration_confirmation"),
    path('vpn/accounts/<password_recovery_token>/password/', CreateResetPasswordRequestApiView.as_view(), name="password_reset"),
]
