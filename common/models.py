from django.db import models
from django.contrib.auth.models import AbstractUser, UserManager
from django.contrib.auth import login, logout
from django.conf import settings
from django.utils.translation import ugettext_lazy as _


class User(AbstractUser):
    """Custom User."""

    username = None
    email = models.EmailField(_('Email address'), unique=True)
    first_name = models.CharField(max_length=100, null=True, blank=True)
    last_name = models.CharField(max_length=100, null=True, blank=True)
    user_created_time = models.CharField(max_length=200, null=True, blank=True)
    created = models.DateTimeField(auto_now_add=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []
    objects = UserManager()

    @property
    def full_name(self):
        """Get full name."""
        names = []
        if self.first_name is not None:
            names.append(self.first_name)
        if self.last_name is not None:
            names.append(self.last_name)
        name = ''
        if len(names) > 0:
            name = " ".join(names)
        return name

    def login(self, request):
        """Log in user."""
        return login(request, self, backend=settings.DEFAULT_AUTHENTICATION_BACKEND)

    def logout(self, request):
        """Log out user."""
        return logout(request)  # , backend=settings.DEFAULT_AUTHENTICATION_BACKEND)
