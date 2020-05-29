from django.urls import path
from .views import (
    ConfirmResetPasswordRequestView,
    ConfirmResetPasswordEmailView,
)

app_name = 'common'

urlpatterns = [
    path('vpn/accounts/<client_email>/<password_reset_token>/', ConfirmResetPasswordRequestView.as_view(), name="confirm_reset_password_request_with_token"),
    path('vpn/accounts/<client_email>/', ConfirmResetPasswordRequestView.as_view(), name="confirm_reset_password_request"),
    path('scratch/emails/reset_password/<password_reset_token>/', ConfirmResetPasswordEmailView.as_view(), name="confirm_reset_password_request"),
]
