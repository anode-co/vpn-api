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


class UserEmailLoginSerializer(serializers.Serializer):
    """Serialize the email field of the User."""

    email_or_username = serializers.CharField()
    password = serializers.CharField()


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
            user = User.objects.get(username=username)
            print("user already exists")
            raise serializers.ValidationError("This username is already registered")
        except User.DoesNotExist:
            print("user does not yet exist")
            pass
        except user.MultipleObjectsReturned:
            print("multiple usernames already exist")
            raise serializers.ValidationError("This username is already registered")
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
