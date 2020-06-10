from rest_framework import serializers
from .models import (
    User,
    PasswordResetRequest,
    PublicKey,
)
from rest_framework.validators import UniqueValidator


class GenericResponseSerializer(serializers.Serializer):
    """Serializer a generic response."""

    status = serializers.CharField()
    message = serializers.CharField(allow_null=True, allow_blank=True)


class UserEmailSerializer(serializers.Serializer):
    """Serialize the email field of the User."""

    email = serializers.EmailField()

    def validate_email(self, email):
        """Validate the email field."""
        try:
            user = User.objects.get(email=email)
            if user.is_confirmed:
                raise serializers.ValidationError("This email address is already registered")
        except User.DoesNotExist:
            pass
        return email

    def save(self, commit=True):
        """Save the User."""
        email = self.validated_data['email']
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
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
            'account_confirmation_status_url'
        ]


class UserAccountConfirmedSerializer(serializers.Serializer):
    """Serialize the status of the account creation."""

    STATUS_SUCCESS = 'pending'
    STATUS_COMPLETE = 'complete'
    STATUS_ERROR = 'error'
    STATUS_CHOICES = [
        (STATUS_SUCCESS, STATUS_SUCCESS),
        (STATUS_COMPLETE, STATUS_COMPLETE),
        (STATUS_ERROR, STATUS_ERROR),
    ]

    status = serializers.ChoiceField(choices=STATUS_CHOICES)
    app_secret_token = serializers.CharField(allow_blank=True, allow_null=True)


class PasswordResetConfirmedSerializer(serializers.Serializer):
    """Serialize the status of the account creation."""

    STATUS_SUCCESS = 'pending'
    STATUS_COMPLETE = 'complete'
    STATUS_ERROR = 'error'
    STATUS_CHOICES = [
        (STATUS_SUCCESS, STATUS_SUCCESS),
        (STATUS_COMPLETE, STATUS_COMPLETE),
        (STATUS_ERROR, STATUS_ERROR),
    ]

    status = serializers.ChoiceField(choices=STATUS_CHOICES)
    app_secret_token = serializers.CharField(allow_blank=True, allow_null=True)


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
        validators = [
            UniqueValidator(queryset=PublicKey.objects.all())
        ]


class PublicKeyOutputSerializer(serializers.ModelSerializer):
    """Serialize an outbound public key."""

    class Meta:
        """Meta information."""

        model = PublicKey
        fields = [
            'public_key_id',
        ]


class PasswordResetInitializationSerializer(serializers.ModelSerializer):
    """Serialize the Password Request Response."""

    class Meta:
        """Meta information."""

        model = PasswordResetRequest
        fields = [
            'password_reset_status_url'
        ]
