from django.urls import path
from .views import (
    ConfirmResetPasswordRequestView,
    ConfirmResetPasswordEmailView,
    ConfirmAccountRegistrationView,
    ConfirmAccountRegistrationEmailView,
)

app_name = 'common'

urlpatterns = [
    path('vpn/accounts/<client_email>/password/reset/<password_reset_token>/', ConfirmResetPasswordRequestView.as_view(), name="confirm_reset_password_request_with_token"),
    path('vpn/accounts/<client_email>/password/reset/', ConfirmResetPasswordRequestView.as_view(), name="confirm_reset_password_request"),

    path('vpn/accounts/<client_email>/confirm/<confirmation_code>/', ConfirmAccountRegistrationView.as_view(), name="confirm_account_registration_with_confirm_code"),
    path('vpn/accounts/<client_email>/confirm/', ConfirmAccountRegistrationView.as_view(), name="confirm_account_registration"),

    path('scratch/emails/confirm_account/<client_email>/', ConfirmAccountRegistrationEmailView.as_view(), name="confirm_account_registration_email"),
    path('scratch/emails/reset_password/<password_reset_token>/', ConfirmResetPasswordEmailView.as_view(), name="confirm_reset_password_email"),
]
