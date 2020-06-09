from rest_framework import serializers
from .models import (
    User,
    PasswordResetToken,
    PublicKey,
)
from rest_framework.validators import UniqueValidator


class GenericResponseSerializer(serializers.Serializer):
    """Serializer a generic response."""

    status = serializers.CharField()
    message = serializers.CharField(allow_null=True, allow_blank=True)


class UserEmailSerializer(serializers.ModelSerializer):
    """Serialize the email field of the User."""

    class Meta:
        """Meta information."""

        model = User
        fields = [
            'email',
        ]


class UserAccountCreatedSerializer(serializers.ModelSerializer):
    """Serialize the email and confirmation fields of the User."""

    class Meta:
        """Meta information."""

        model = User
        fields = [
            'email',
            'confirmation_code'
        ]


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


class PasswordResetTokenSerializer(serializers.ModelSerializer):
    """Serialize the Password Request Response."""

    class Meta:
        """Meta information."""

        model = PasswordResetToken
        fields = [
            'password_reset_token',
            'password_reset_status_url'
        ]
