from django.views import View
from django.shortcuts import render
from django.shortcuts import get_object_or_404
from .models import (
    PasswordResetToken
)
from .forms import (
    ConfirmPasswordResetForm
)

# 2zeopb6hvr418nplnckwkvj2p13o81j1448oxm39q3rzh3pojthsi0b5kt6mwrls


class ConfirmResetPasswordRequestView(View):
    """Check on the status of a password reset process."""

    template_file = 'templates/common/reset_password_confirmed.html'

    def render_complete(self, request, password_reset_token):
        """Render the confirmation page."""
        context = {
            'password_reset_token': password_reset_token,
            'user': password_reset_token.user,
        }
        return render(request, 'common/reset_password_confirmed.html', context)

    def get(self, request, client_email, password_reset_token=None):
        """Confirm a password reset request."""
        if password_reset_token is None:
            password_reset_token_str = request.GET.get('password_reset_token')
            if password_reset_token_str is not None and password_reset_token_str != '':
                password_reset_token = get_object_or_404(PasswordResetToken, password_reset_token=password_reset_token_str)
                password_reset_token.confirm()
                return self.render_complete(request, password_reset_token)
            else:
                form = ConfirmPasswordResetForm()
                context = {
                    'email': client_email,
                    'form': form
                }
                return render(request, 'common/confirm_password_token.html', context)
        else:
            password_reset_token = get_object_or_404(PasswordResetToken, password_reset_token=password_reset_token, user__email=client_email, is_complete=False)
            password_reset_token.confirm()
            return self.render_complete(request, password_reset_token)


class ConfirmResetPasswordEmailView(View):
    """Preview the confirmation email."""

    template_file = 'common/emails/customer__reset_password_request.txt'

    def get(self, request, password_reset_token):
        """Preview the email."""
        password_reset_token = get_object_or_404(PasswordResetToken, password_reset_token=password_reset_token)
        print("hello")
        print(password_reset_token)
        context = {
            'password_reset_token': password_reset_token,
            'user': password_reset_token.user,
            'password_reset_confirmation_url': password_reset_token.get_password_reset_confirmation_url(request)
        }
        return render(request, self.template_file, context)
