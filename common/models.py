import traceback
from django.db import models
from django.contrib.auth.models import AbstractUser, UserManager
from django.contrib.auth import login, logout
from django.conf import settings
from django.utils.translation import ugettext_lazy as _
from fastecdsa import keys, curve
from django.db.models.signals import pre_save, post_save
import string
import random
from django.urls import reverse
from django.template.loader import render_to_string
from django.core.mail import EmailMultiAlternatives


class Utilities:
    """Generic utilities."""

    @staticmethod
    def to_base32(n):
        """Convert integer to base32."""
        alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        return "0" if not n else Utilities.to_base32(n // 32).lstrip("0") + alphabet[n % 32]


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
    public_key_id = models.CharField(max_length=32, null=True, blank=True)
    public_key = models.CharField(max_length=150, null=True, blank=True)
    private_key = models.CharField(max_length=64, null=True, blank=True)
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

    def create_password_request(self):
        """Create a new password request."""
        password_reset_token = PasswordResetToken()
        password_reset_token.user = self
        password_reset_token.save()
        return password_reset_token

    def login(self, request):
        """Log in user."""
        return login(request, self, backend=settings.DEFAULT_AUTHENTICATION_BACKEND)

    def logout(self, request):
        """Log out user."""
        return logout(request)  # , backend=settings.DEFAULT_AUTHENTICATION_BACKEND)

    @classmethod
    def pre_save(cls, instance, *args, **kwargs):
        """Pre-save script. Generate public/private key."""
        if instance.public_key is None:
            private_key, public_key = keys.gen_keypair(curve.P256)
            instance.public_key = Utilities.to_base32(public_key.x) + Utilities.to_base32(public_key.y)
            instance.private_key = Utilities.to_base32(private_key)
        if instance.public_key_id is None:
            instance.public_key_id = "{}-{}".format(instance.public_key[:10], instance.id)


pre_save.connect(User.pre_save, sender=User)


class PublicKey(models.Model):
    """Public keys."""

    public_key_id = models.CharField(max_length=32, null=True, blank=True)
    public_key = models.TextField(max_length=500, null=True, blank=True)
    algorithm = models.CharField(max_length=32, default='rsa-sha256')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        """Represent as string."""
        return self.public_key

    @classmethod
    def post_save(cls, sender, instance, created, **kwargs):
        """Sent when post_save signal is sent."""
        print("running public_Key post save script")
        print(created)
        print(cls)
        print(instance)
        print(instance.pk)
        print(instance.algorithm)
        print(instance.public_key)
        if instance.public_key_id is None or instance.public_key_id == '':
            instance.public_key_id = "{}-{}-{}".format(instance.algorithm, instance.public_key[27:10], instance.id)
            instance.save()


post_save.connect(PublicKey.post_save, sender=PublicKey)


class PasswordResetToken(models.Model):
    """Password reset token. Created when a user requests to reset their password."""

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    password_reset_token = models.CharField(max_length=120, null=True, blank=True)
    is_complete = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    password_reset_status_url = None

    def __str__(self):
        """Represent as string."""
        return self.password_reset_token

    def confirm(self):
        """Set is_complete to True and save."""
        self.is_complete = True
        self.save()

    def get_password_reset_status_url(self, request):
        """Return the reset password confirmation status API endpoint."""
        return request.build_absolute_uri(reverse('common_api_0_3:check_password_reset_confirmation', kwargs={'client_email': self.user.email, 'password_reset_token': self.password_reset_token}))

    def get_password_reset_confirmation_url(self, request):
        """Return the reset password confirmation status API endpoint."""
        return request.build_absolute_uri(reverse('common:confirm_reset_password_request_with_token', kwargs={'client_email': self.user.email, 'password_reset_token': self.password_reset_token}))

    def generate_token(self):
        """Generate a token."""
        token_length = 64
        alphabet = string.digits + string.ascii_lowercase
        self.password_reset_token = ''.join(random.choice(alphabet) for i in range(token_length))

    def send_password_reset_confirmation_email(self, request, template_set_name='common/emails/customer__reset_password_request', fail_silently=False):
        """Send an email to the user confirming their password reset request."""
        if self.password_reset_token is None:
            self.generate_token()

        context = {
            'password_reset_token': self,
            'user': self.user,
            'password_reset_confirmation_url': self.get_password_reset_confirmation_url(request)
        }
        password_reset_email = HtmlEmail(
            template_set_name,
            settings.DEFAULT_FROM_EMAIL,
            [self.user.email],
            context
        )
        password_reset_email.send(fail_silently)

    @classmethod
    def pre_save(cls, instance, *args, **kwargs):
        """Pre-save script. Generate public/private key."""
        if instance.password_reset_token is None:
            instance.generate_token()


pre_save.connect(PasswordResetToken.pre_save, sender=PasswordResetToken)


class HtmlEmail:
    """EmailMultiAlternative wrapper."""

    # This code is open source, created by backupbrain@gmail.com

    email_multi_alternative = None
    template_set_name = None
    text_template = None
    html_template = None
    subject_template = None

    def __init__(self, template_set_name, from_email, to_emails, context, reply_to=None, headers=None):
        """Initialize the email."""
        subject_template_file = "{}_subject.txt".format(template_set_name)
        subject_template = render_to_string(subject_template_file, context)
        text_template_file = "{}.txt".format(template_set_name)
        text_template = None

        try:
            text_template = render_to_string(text_template_file, context)
        except Exception:
            print("problem creating text template")
            traceback.print_exc()
        html_template_file = "{}.html".format(template_set_name)
        html_template = None
        try:
            html_template = render_to_string(html_template_file, context)
        except Exception:
            print("problem creating html template")
            traceback.print_exc()
            pass
        self.email_multi_alternative = EmailMultiAlternatives(
            subject_template,
            text_template,
            from_email,
            to_emails,
            reply_to=reply_to,
            headers=headers
        )
        if html_template is not None and html_template != '':
            self.email_multi_alternative.attach_alternative(html_template, "text/html")
            if text_template is None:
                self.email_multi_alternative.content_subtype = 'html'
        if text_template is None and (html_template is None or html_template == ''):
            raise Exception('No templates found')

    def attach(self, attachment_name, file_data, mime_type):
        """Attach a file."""
        self.email_multi_alternative.attach(attachment_name, file_data, mime_type)

    def attach_file(self, path):
        """Attach a file."""
        self.email_multi_alternative.attach_file(path)

    def send(self, fail_silently=False):
        """Send email."""
        self.email_multi_alternative.send(fail_silently)
