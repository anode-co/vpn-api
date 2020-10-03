from rest_framework import serializers
from .models import (
    User,
    PasswordResetRequest,
    PublicKey,
)


class GenericResponseSerializer(serializers.Serializer):
    """Serializer a generic response."""

    status = serializers.CharField()
    message = serializers.CharField(allow_null=True, allow_blank=True)


class UsernameSerializer(serializers.Serializer):
    """Serialize a username."""

    username = serializers.CharField()


class UsernameEmailSerializer(serializers.Serializer):
    """Serialize a username and email."""

    email = serializers.EmailField()
    username = serializers.CharField()


class UserEmailLoginSerializer(serializers.Serializer):
    """Serialize the email field of the User."""

    email_or_username = serializers.CharField()
    password = serializers.CharField()


class UserPublicKeyLoginSerializer(serializers.ModelSerializer):
    """Serialize the Public Key of the User."""

    class Meta:
        """Meta information."""

        model = User
        fields = ['public_key']


class SetEmailAddressSerializer(serializers.Serializer):
    """Serialize the user's email address."""

    email = serializers.EmailField()

    def validate_email(self, email):
        """Validate the email field."""
        try:
            User.objects.get(email=email)
            raise serializers.ValidationError("This email address is already registered")
        except User.DoesNotExist:
            pass
        return email

    def save(self, user, commit=True):
        """Update the user's email."""
        email = self.validated_data['email']
        if user.email != User.get_default_email(user.username):
            raise serializers.ValidationError("This account already has an email")
        else:
            user.email = email
        if commit is True:
            user.save()
        return user


class SetInitialPasswordSerializer(serializers.Serializer):
    """Serialize the input initial password."""

    password = serializers.CharField()

    def save(self, user, commit=True):
        """Save the user's new password."""
        password = self.validated_data['password']
        user.set_password(password)
        if commit is True:
            user.save()
        return user


class CreateUserSerializer(serializers.Serializer):
    """Serialize the email field of the User."""

    username = serializers.CharField()

    def validate_username(self, username):
        """Validate the email field."""
        try:
            User.objects.get(username=username)
            print("user already exists")
            raise serializers.ValidationError("This username is already registered")
        except User.MultipleObjectsReturned:
            print("multiple usernames already exist")
            raise serializers.ValidationError("This username is already registered")
        except User.DoesNotExist:
            print("user does not yet exist")
            pass
        return username

    def save(self, cjdns_public_key, commit=True):
        """Save the User."""
        username = self.validated_data['username']
        self.validated_data['email'] = User.get_default_email(username)
        self.validated_data['public_key'] = cjdns_public_key
        user = User.objects.create(**self.validated_data)
        if commit is True:
            user.save()
        return user


class UserAccountCreatedSerializer(serializers.ModelSerializer):
    """Serialize the email and confirmation fields of the User."""

    class Meta:
        """Meta information."""

        model = User
        fields = [
            'password_recovery_token'
        ]


class EmailConfirmationSerializer(serializers.ModelSerializer):
    """Serialize the confirmation field of the User."""

    class Meta:
        """Meta information."""

        model = User
        fields = [
            'account_confirmation_status_url',
        ]


class UserAccountConfirmedSerializer(serializers.Serializer):
    """Serialize the status of the account creation."""

    STATUS_PENDING = 'pending'
    STATUS_COMPLETE = 'complete'
    STATUS_CHOICES = [
        (STATUS_PENDING, STATUS_PENDING),
        (STATUS_COMPLETE, STATUS_COMPLETE),
    ]

    status = serializers.ChoiceField(choices=STATUS_CHOICES)
    backup_wallet_password = serializers.CharField(allow_blank=True, allow_null=True)


class UserAccountPendingSerializer(serializers.Serializer):
    """Serialize the status of the account creation."""

    STATUS_PENDING = 'pending'
    STATUS_COMPLETE = 'complete'
    STATUS_CHOICES = [
        (STATUS_COMPLETE, STATUS_COMPLETE),
        (STATUS_PENDING, STATUS_PENDING),
    ]

    status = serializers.ChoiceField(choices=STATUS_CHOICES)


class PasswordResetPendingSerializer(serializers.Serializer):
    """Serialize the status of the account creation."""

    STATUS_PENDING = 'pending'
    STATUS_COMPLETE = 'complete'
    STATUS_CHOICES = [
        (STATUS_PENDING, STATUS_PENDING),
        (STATUS_COMPLETE, STATUS_COMPLETE),
    ]

    status = serializers.ChoiceField(choices=STATUS_CHOICES)


class PasswordResetConfirmedSerializer(serializers.Serializer):
    """Serialize the status of the account creation."""

    STATUS_PENDING = 'pending'
    STATUS_COMPLETE = 'complete'
    STATUS_CHOICES = [
        (STATUS_PENDING, STATUS_PENDING),
        (STATUS_COMPLETE, STATUS_COMPLETE),
    ]

    status = serializers.ChoiceField(choices=STATUS_CHOICES)
    password_reset_token = serializers.CharField(allow_blank=True, allow_null=True)


class UserPublicKeySerializer(serializers.ModelSerializer):
    """Serialize the email field of the User."""

    class Meta:
        """Meta information."""

        model = User
        fields = [
            'public_key_id',
            'public_key',
        ]


class PublicKeyInputSerializer(serializers.ModelSerializer):
    """Serialize inbound public key."""

    class Meta:
        """Meta information."""

        model = PublicKey
        fields = [
            'public_key',
            'algorithm'
        ]

        def clean_public_key(self, public_key):
            """Make sure public key is unique."""
            existing_public_keys = PublicKey.objects.filter(public_key=public_key)
            if existing_public_keys.exists():
                raise serializers.ValidationError("This public key is already registered")
            return public_key


class PublicKeyOutputSerializer(serializers.ModelSerializer):
    """Serialize an outbound public key."""

    class Meta:
        """Meta information."""

        model = PublicKey
        fields = [
            'public_key_id',
        ]


class CanonicalPublicKeyOutputSerializer(serializers.ModelSerializer):
    """Serialize an outbound public key."""

    class Meta:
        """Meta information."""

        model = PublicKey
        fields = [
            'public_key',
        ]


class PasswordResetInitializationSerializer(serializers.ModelSerializer):
    """Serialize the Password Request Response."""

    class Meta:
        """Meta information."""

        model = PasswordResetRequest
        fields = [
            'password_reset_status_url'
        ]


class ChangePasswordSerializer(serializers.Serializer):
    """Serialize the  password reset request."""

    current_password = serializers.CharField()
    new_password = serializers.CharField()

    user = None

    def __init__(self, *args, **kwargs):
        """Initialize the  serializer."""
        self.user = kwargs.pop('user')
        super(ChangePasswordSerializer, self).__init__(*args, **kwargs)

    def validate_current_password(self, current_password):
        """Validate the current password."""
        if self.user.check_password(current_password) is False:
            raise serializers.ValidationError("The username and/or password combination does not match")
        return current_password

    def save(self, commit=True):
        """Save the user's new password."""
        new_password = self.validated_data['new_password']
        self.user.set_password(new_password)
        if commit is True:
            self.user.save()
        return self.user


class PasswordResetChangePasswordSerializer(serializers.Serializer):
    """Set a new password for a user who forgot theirs."""

    password_reset_token = serializers.CharField()
    new_password = serializers.CharField()

    email_or_username = None
    user = None
    password_reset_request = None

    def __init__(self, *args, **kwargs):
        """Initialize the  serializer."""
        self.email_or_username = kwargs.pop('email_or_username')
        super(self.__class__, self).__init__(*args, **kwargs)

    def validate_password_reset_token(self, password_reset_token):
        """Validate the current password."""
        try:
            reset_request = PasswordResetRequest.objects.select_related('user').get(password_reset_token=password_reset_token, user__email=self.email_or_username)
        except PasswordResetRequest.DoesNotExist:
            reset_request = PasswordResetRequest.objects.select_related('user').get(password_reset_token=password_reset_token, user__username=self.email_or_username)
        except PasswordResetRequest.DoesNotExist:
            raise serializers.ValidationError("The username and/or password combination does not match")
        self.password_reset_request = reset_request
        self.user = reset_request.user
        return password_reset_token

    def save(self, commit=True):
        """Save the user's new password."""
        new_password = self.validated_data['new_password']
        self.user.set_password(new_password)
        if commit is True:
            self.user.save()
            self.password_reset_request.delete()
        return self.user
