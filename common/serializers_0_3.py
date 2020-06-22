from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password  # TODO: remove for wallet integration
from django.core.exceptions import ValidationError  # TODO: remove for wallet integration
from .models import (
    User,
    PasswordResetRequest,
    PublicKey,
)


class GenericResponseSerializer(serializers.Serializer):
    """Serializer a generic response."""

    status = serializers.CharField()
    message = serializers.CharField(allow_null=True, allow_blank=True)


class UserEmailSerializer(serializers.Serializer):
    """Serialize the email field of the User."""

    email = serializers.EmailField()
    username = serializers.CharField()
    password = serializers.CharField()   # TODO: Remove for wallet integration

    def validate_email(self, email):
        """Validate the email field."""
        try:
            user = User.objects.get(email=email)
            if user.is_confirmed:
                raise serializers.ValidationError("This email address is already registered")
        except User.DoesNotExist:
            pass
        return email

    def validate_username(self, username):
        """Validate the email field."""
        try:
            user = User.objects.get(username=username)
            if user.is_confirmed:
                raise serializers.ValidationError("This username address is already registered")
        except User.DoesNotExist:
            pass
        return username

    def validate_password(self, password):
        """Validate the password field."""
        # TODO: Remove for  wallet integration
        validate_password(password)
        return password

    def save(self, commit=True):
        """Save the User."""
        email = self.validated_data['email']
        username = self.validated_data['username']
        password = self.validated_data['password']   # TODO: Remove for wallet integration
        try:
            user = User.objects.get(email=email)
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            user = User.objects.create(**self.validated_data)
            user.set_password(password)   # TODO: Remove for wallet integration
            if commit is True:
                user.save()
        return user


class UserAccountCreatedSerializer(serializers.ModelSerializer):
    """Serialize the email and confirmation fields of the User."""

    class Meta:
        """Meta information."""

        model = User
        fields = [
            'account_confirmation_status_url',
            'password_recovery_token'
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
    backup_wallet_password = serializers.CharField(allow_blank=True, allow_null=True)


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
