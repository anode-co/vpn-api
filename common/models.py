from django.db import models
from django.contrib.auth.models import AbstractUser, UserManager
from django.contrib.auth import login, logout
from django.conf import settings
from django.utils.translation import ugettext_lazy as _


class UserManager(UserManager):
    """Define a model manager for User model with no username field."""

    use_in_migrations = True

    def _create_user(self, email, password, **extra_fields):
        """Create and save a User with the given email and password."""
        if not email:
            raise ValueError('The given email must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, email, password=None, **extra_fields):
        """Create and save a regular User with the given email and password."""
        extra_fields.setdefault('is_staff', False)
        extra_fields.setdefault('is_superuser', False)
        return self._create_user(email, password, **extra_fields)

    def create_superuser(self, email, password, **extra_fields):
        """Create and save a SuperUser with the given email and password."""
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')
        return self._create_user(email, password, **extra_fields)


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
