from crispy_forms.helper import FormHelper
from django import forms
from crispy_forms.layout import Submit
from django.utils.translation import ugettext_lazy as _


class ConfirmPasswordResetForm(forms.Form):
    """Confirm Password Reset."""

    password_reset_token = forms.CharField(required=True)

    def __init__(self, *args, **kwargs):
        """Initialize the form with Crispy FormHelper."""
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.form_id = 'id-confirmpasswordreset'
        self.helper.form_method = 'get'

        self.helper.add_input(Submit('submit', _('Confirm')))
