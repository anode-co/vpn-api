from django.views import View
from django.shortcuts import render
from django.shortcuts import get_object_or_404
from .models import (
    PasswordResetToken,
    User,
)
from .forms import (
    ConfirmPasswordResetForm,
    ConfirmAccountRegistrationForm
)

# 2zeopb6hvr418nplnckwkvj2p13o81j1448oxm39q3rzh3pojthsi0b5kt6mwrls


class ConfirmAccountRegistrationView(View):
    """Check on the status of a password reset process."""

    template_file = 'templates/common/confirm_account_registration.html'

    def render_complete(self, request, user, confirmation_code):
        """Render the confirmation page."""
        context = {
            'confirmation_code': confirmation_code,
            'user': user,
        }
        return render(request, 'common/account_registration_confirmed.html', context)

    def get(self, request, client_email, confirmation_code=None):
        """Confirm a password reset request."""
        if confirmation_code is None:
            confirmation_code = request.GET.get('code')
            if confirmation_code is not None and confirmation_code != '':
                user = get_object_or_404(User, email=client_email, confirmation_code=confirmation_code)
                user.confirm_account()
                return self.render_complete(request, user, confirmation_code)
            else:
                form = ConfirmAccountRegistrationForm()
                context = {
                    'email': client_email,
                    'form': form
                }
                return render(request, 'common/confirm_account_registration.html', context)
        else:
            user = get_object_or_404(User, email=client_email, confirmation_code=confirmation_code)
            user.confirm_account()
            return self.render_complete(request, user, confirmation_code)


class ConfirmResetPasswordRequestView(View):
    """Check on the status of a password reset process."""

    template_file = 'templates/common/confirm_password_token.html'

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


class ConfirmAccountRegistrationEmailView(View):
    """Preview the confirmation email."""

    template_file = 'common/emails/customer__create_account_confirmation.txt'

    def get(self, request, client_email):
        """Preview the email."""
        user = get_object_or_404(User, email=client_email)
        print("hello")
        print(user)
        context = {
            'user': user,
            'account_confirmation_url': user.get_account_confirmation_url(request)
        }
        return render(request, self.template_file, context)


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
