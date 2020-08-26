from rest_framework.generics import GenericAPIView
from rest_framework.response import Response
from rest_framework import status
from django.shortcuts import get_object_or_404
from django.http import Http404
from .models import (
    User,
    PasswordResetRequest,
    PublicKey,
)
from .serializers_0_3 import (
    GenericResponseSerializer,
    CreateUserSerializer,
    PasswordResetInitializationSerializer,
    PasswordResetConfirmedSerializer,
    PasswordResetPendingSerializer,
    UserAccountCreatedSerializer,
    UserAccountConfirmedSerializer,
    UserAccountPendingSerializer,
    CanonicalPublicKeyOutputSerializer,
    UserEmailLoginSerializer,
    SetEmailAddressSerializer,
    SetInitialPasswordSerializer,
    UserPublicKeyLoginSerializer,
    EmailConfirmationSerializer,
    UsernameSerializer,
)
from drf_yasg.utils import swagger_auto_schema
from django.utils import timezone
from .permissions import (
    CsrfExemptMixin,
    HttpCjdnsAuthorizationRequiredMixin,
)
from django.contrib.auth import authenticate, logout  # TODO: Remove for wallet integration


class AuthTestApiView(HttpCjdnsAuthorizationRequiredMixin, GenericAPIView):
    """Test Crypto Auth Mixin."""

    def get(self, request):
        """GET method."""
        return Response({"status": "authorized"})

    def post(self, request):
        """GET method."""
        request.data['publicKey'] = self.auth_verified_cjdns_public_key
        return Response(request.data)


class GetCoordinatorPublicKeyApiView(GenericAPIView):
    """Get this server's public key.

    This server has a public  key used for cjdns and for encrypted messages
    This endpoint provides that public key.
    """

    serializer_class = CanonicalPublicKeyOutputSerializer

    @swagger_auto_schema(responses={200: CanonicalPublicKeyOutputSerializer})
    def get(self, request):
        """Get this server's public key.

        This server has a public  key used for cjdns and for encrypted messages
        This endpoint provides that public key.
        """
        public_key = get_object_or_404(PublicKey, public_key_id='coordinator')
        output_serializer = self.get_serializer(public_key)
        return Response(output_serializer.data)


class UsernameApiView(HttpCjdnsAuthorizationRequiredMixin, CsrfExemptMixin, GenericAPIView):
    """Generate a new username.

    Not all users want to decide on their own username, so
    non-assigned usernames can be generated on the fly.
    """

    serializer_class = UsernameSerializer

    @swagger_auto_schema(responses={400: GenericResponseSerializer, 200: UsernameSerializer})
    def get(self, request):
        """GET method."""
        username = User.generate_username()
        if username is False:
            output = {"status": "error", "message": "New username could not be generated"}
            serializer = GenericResponseSerializer(data=output)
            serializer.is_valid()
            return Response(serializer.data, status=status.HTTP_400_BAD_REQUEST)
        output = {'username': username}
        serializer = self.get_serializer(data=output)
        serializer.is_valid()
        return Response(serializer.data)


class AccountLoginApiView(HttpCjdnsAuthorizationRequiredMixin, CsrfExemptMixin, GenericAPIView):
    """When a new email address is submitted.

    the email address is registered with the system and a unique token
    is generated for that email.
    This token must be kept secret and is used for operations
    related to account management.
    """

    serializer_class = UserEmailLoginSerializer

    @swagger_auto_schema(responses={401: None, 200: None})
    def post(self, request):
        """GET method."""
        input_serializer = self.serializer_class(data=request.data)
        input_serializer.is_valid(raise_exception=True)
        email = input_serializer.data['email_or_username']
        username = input_serializer.data['email_or_username']
        password = input_serializer.data['password']
        is_authorized = False

        print("Attempting to authorize email={}, password={}".format(email, password))
        user = authenticate(email=email, password=password)
        if user is None:
            print("Attempting to authorize username={}, password={}".format(username, password))
            # Can't use authorization system because we originally
            # constructed the User to not use a username
            try:
                user = User.objects.get(username=username)
                if user.check_password(password) is True:
                    is_authorized = True
            except User.DoesNotExist:
                is_authorized = False
        else:
            is_authorized = True

        if is_authorized is True:
            if user.public_key != self.auth_verified_cjdns_public_key:
                user.public_key = self.auth_verified_cjdns_public_key
                user.save()
            return Response(None, status.HTTP_200_OK)
        else:
            return Response(None, status.HTTP_401_UNAUTHORIZED)


class AccountLogoutApiView(HttpCjdnsAuthorizationRequiredMixin, CsrfExemptMixin, GenericAPIView):
    """Log out - disconnect the CJDNS public key.

    Disconnect the existing cjdns public key from the user's account
    """

    serializer_class = UserEmailLoginSerializer

    @swagger_auto_schema(responses={200: GenericResponseSerializer})
    def post(self, request):
        """POST method."""
        input_serializer = self.serializer_class(data=request.data)
        input_serializer.is_valid(raise_exception=True)
        email = input_serializer.data['email_or_username']
        username = input_serializer.data['email_or_username']
        password = input_serializer.data['password']
        is_authorized = False

        print("Attempting to authorize email={}, password={}".format(email, password))
        cjdns_public_key = self.auth_verified_cjdns_public_key
        user = authenticate(email=email, password=password, public_key=cjdns_public_key)
        if user is None:
            print("Attempting to authorize username={}, password={}".format(username, password))
            # Can't use authorization system because we originally
            # constructed the User to not use a username
            try:
                user = User.objects.get(username=username)
                if user.check_password(password) is True:
                    is_authorized = True
            except User.DoesNotExist:
                is_authorized = False
        else:
            is_authorized = True

        if is_authorized is True:
            user.public_key = None
            user.save()
            response_data = {
                'status': 'success',
            }
            response = GenericResponseSerializer(data=response_data)
            response.is_valid()
            return Response(response.data, status.HTTP_200_OK)
        else:
            return Response(None, status.HTTP_401_UNAUTHORIZED)


class CreateAccountApiView(HttpCjdnsAuthorizationRequiredMixin, CsrfExemptMixin, GenericAPIView):
    """When a new email address is submitted.

    the email address is registered with the system and a unique token
    is generated for that email.
    This token must be kept secret and is used for operations
    related to account management.
    """

    serializer_class = UserAccountCreatedSerializer

    @swagger_auto_schema(responses={400: 'Invalid request', 201: UserAccountCreatedSerializer})
    def post(self, request):
        """Register a new email address.

        (REQUIRES AUTHORIZATION). The email address is registered with the system and an email
        is sent to that email with a confirmation link.  The user opens the
        confirmation link, which confirms their registration.
        Meanwhile, the "Check status of new email registration" will reply with
        {"status":"pending"} until the user has opened the confirm URL.
        """
        input_serializer = CreateUserSerializer(data=request.data)
        input_serializer.is_valid(raise_exception=True)
        user = input_serializer.save(self.auth_verified_cjdns_public_key)
        # user.send_account_registration_confirmation_email(request)
        # user.account_confirmation_status_url = user.get_account_confirmation_status_url(request)
        output_serializer = self.get_serializer(user)
        return Response(output_serializer.data, status.HTTP_201_CREATED)


class CreateAccountConfirmationStatusApiView(HttpCjdnsAuthorizationRequiredMixin, GenericAPIView):
    """Check on the status of a password reset process."""

    serializer_class = UserAccountConfirmedSerializer

    @swagger_auto_schema(responses={200: UserAccountConfirmedSerializer, 202: UserAccountPendingSerializer, 404: 'Not Found'})
    def get(self, request, username):
        """Check status of new account registration.

        (REQUIRES AUTHORIZATION). When a new account is registered with the
        "Register a new account" method, this method responds responds
        with a {"status":"pending"} until the user confirms their email address.
        Once the user confirms their email address, this method returns the
        appSecretToken which can be used to decrypt the wallet
        on the user's app. Once viewed, the password request is destroyed and
        cannot be viewed again.
        """
        user = get_object_or_404(User, username=username)
        http_status = status.HTTP_202_ACCEPTED
        output = {'status': 'pending'}
        if user.is_confirmed is True:
            if user.is_backup_wallet_password_seen is True:
                http_status = status.HTTP_200_OK
                output = {'status': 'complete'}
            else:
                http_status = status.HTTP_200_OK
                output = {'status': 'complete', 'backup_wallet_password': user.backup_wallet_password}
                # for security reasons, disallow access to this backup_wallet_password in the future
                user.set_backup_wallet_password_seen()
        serializer = self.serializer_class(data=output)
        serializer.is_valid()
        return Response(serializer.data, status=http_status)


class SetInitialAccountPasswordApiView(HttpCjdnsAuthorizationRequiredMixin, GenericAPIView):
    """Set the initial account password."""

    serializer_class = SetInitialPasswordSerializer

    @swagger_auto_schema(responses={200: GenericResponseSerializer, 403: GenericResponseSerializer})
    def post(self, request, username):
        """Set the initial password for the user.

        After an account has been created, a user may set a password
        """
        user = get_object_or_404(User, username=username, public_key=self.auth_verified_cjdns_public_key)
        serializer = self.get_serializer(user, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        # TODO: move this function to the validate() method of the serializer
        if user.has_usable_password() is False or user.password == '':
            serializer.save(user)
            output = {"status": "success", "message": "initial password set"}
            output_serializer = GenericResponseSerializer(data=output)
            output_serializer.is_valid()
            return Response(output_serializer.data)
        else:
            output = {"status": "failed", "message": "a password is already set for this account"}
            output_serializer = GenericResponseSerializer(data=output)
            output_serializer.is_valid()
            return Response(output_serializer.data, status=status.HTTP_403_FORBIDDEN)


class SetEmailAddressApiView(HttpCjdnsAuthorizationRequiredMixin, GenericAPIView):
    """Set the initial account password."""

    serializer_class = SetEmailAddressSerializer

    @swagger_auto_schema(responses={200: EmailConfirmationSerializer, 400: None})
    def post(self, request, username):
        """Set the initial password for the user.

        After an account has been created, a user may set a password
        """
        user = get_object_or_404(User, username=username, public_key=self.auth_verified_cjdns_public_key)
        serializer = self.get_serializer(user, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save(user)
        user.send_account_registration_confirmation_email(request)
        user.account_confirmation_status_url = user.get_account_confirmation_status_url(request)
        ouput_serializer = EmailConfirmationSerializer(user)
        return Response(ouput_serializer.data)


class AccountPublicKeyApiView(HttpCjdnsAuthorizationRequiredMixin, GenericAPIView):
    """Account Public Key."""

    serializer_class = UserPublicKeyLoginSerializer

    def get(self, request, username):
        """Get the user's public key."""
        cjdns_public_key = self.auth_verified_cjdns_public_key
        user = get_object_or_404(User, username=username, public_key=cjdns_public_key)
        serializer = self.get_serializer(user)
        return Response(serializer.data)

    def post(self, request, username):
        """Add cjdns public key to user."""
        cjdns_public_key = self.auth_verified_cjdns_public_key
        user = get_object_or_404(User, username=username)
        user.public_key = cjdns_public_key
        user.save()
        serializer = self.get_serializer(user)
        return Response(serializer.data)

    def delete(self, request, username):
        """Detach cjdns public key from user."""
        cjdns_public_key = self.auth_verified_cjdns_public_key
        user = get_object_or_404(User, username=username, public_key=cjdns_public_key)
        user.public_key = None
        user.save()
        serializer = self.get_serializer(user)
        return Response(serializer.data)


class CreateResetPasswordRequestApiView(HttpCjdnsAuthorizationRequiredMixin, GenericAPIView):
    """Create a password reset request."""

    serializer_class = PasswordResetInitializationSerializer

    @swagger_auto_schema(responses={200: PasswordResetConfirmedSerializer, 202: PasswordResetPendingSerializer, 404: 'Not Found'})
    def get(self, request, password_recovery_token):
        """Check the status of a password reset request.

        (REQUIRES AUTHORIZATION). When the user goes to the web page provided in the password reset
        two factor authorization email, sent with the
        "Initialize a password reset request" method, the status of their
        password reset request will change from "pending" to "success."
        When the status changes to "success," the email's appSecretKey
        will be revealed one time only and the password reset request will
        be destroyed.
        """
        now = timezone.now()
        password_reset_token = PasswordResetRequest.objects.select_related('user').filter(user__password_recovery_token=password_recovery_token, expires_on__gt=now).order_by('-created_at').first()
        if password_reset_token is None:
            raise Http404
        http_status = status.HTTP_201_CREATED
        output = {'status': 'pending'}
        if password_reset_token.is_complete is True:
            http_status = status.HTTP_200_OK
            output = {'status': 'complete', 'backup_wallet_password': password_reset_token.user.backup_wallet_password}
            # for security reasons, delete any related PasswordResetRequests
            PasswordResetRequest.objects.filter(user__password_recovery_token=password_recovery_token).delete()
        serializer = PasswordResetConfirmedSerializer(data=output)
        serializer.is_valid()
        return Response(serializer.data, status=http_status)

    @swagger_auto_schema(responses={201: PasswordResetInitializationSerializer, 404: 'Not Found'}, request_body=None)
    def post(self, request, password_recovery_token):
        """Initialize a password reset request.

        (REQUIRES AUTHORIZATION). When password registration request is created, the user of
        who owns <password_reset_token> is sent a confirmation email as a
        two factor authentication. The user must confirm their email
        in  order to release the appSecretKey to the VPN app, which
        can be used to decrypt the app wallet and change the password.
        """
        user = get_object_or_404(User, password_recovery_token=password_recovery_token)
        # for securtiy reasons, delete all previous password reset requests
        PasswordResetRequest.objects.filter(user=user).delete()
        password_reset_token = user.create_password_request()
        password_reset_token.send_password_reset_confirmation_email(request)
        password_reset_token.password_reset_status_url = password_reset_token.get_password_reset_status_url(request)
        serializer = self.serializer_class(password_reset_token)
        return Response(serializer.data, status=status.HTTP_202_ACCEPTED)
