from django.urls import path
from .views_api_0_3 import (
    CreateAccountApiView,
    CreateResetPasswordRequestApiView,
    CreateAccountConfirmationStatusApiView,
    SetInitialAccountPasswordApiView,
    AccountLoginApiView,
    SetEmailAddressApiView,
    AccountPublicKeyApiView,
    UsernameApiView,
    AccountChangePasswordApiView,
)

app_name = 'common_api_0_3_account_management'

urlpatterns = [
    path('vpn/accounts/', CreateAccountApiView.as_view(), name="Register New Client Account"),
    path('vpn/accounts/username/', UsernameApiView.as_view(), name="Generate a new username"),
    path('vpn/accounts/<username>/confirmstatus/', CreateAccountConfirmationStatusApiView.as_view(), name="check_account_registration_confirmation"),
    path('vpn/accounts/<username>/setinitialpassword/', SetInitialAccountPasswordApiView.as_view(), name="set_initial_account_password"),
    path('vpn/accounts/<password_recovery_token>/password/', CreateResetPasswordRequestApiView.as_view(), name="password_reset"),

    path('vpn/accounts/authorize/', AccountLoginApiView.as_view(), name="account_login"),

    path('vpn/accounts/<username>/initialemail/', SetEmailAddressApiView.as_view(), name="account_register_email"),
    path('vpn/accounts/<username>/initialpassword/', SetInitialAccountPasswordApiView.as_view(), name="account_set_initial_password"),

    path('vpn/accounts/<username>/changepassword/', AccountChangePasswordApiView.as_view(), name="check_account_registration_confirmation"),

    path('vpn/accounts/<username>/publickey/', AccountPublicKeyApiView.as_view(), name="account_public_key"),
]
