from rest_framework.generics import GenericAPIView
from rest_framework.response import Response
from rest_framework import status
from django.shortcuts import get_object_or_404
from django.http import Http404
from .models import (
    User,
    PasswordResetRequest,
)
from .serializers_0_3 import (
    UserEmailSerializer,
    PasswordResetInitializationSerializer,
    PasswordResetConfirmedSerializer,
    PasswordResetPendingSerializer,
    PublicKeyInputSerializer,
    PublicKeyOutputSerializer,
    UserAccountCreatedSerializer,
    UserAccountConfirmedSerializer,
    UserAccountPendingSerializer,
)
from drf_yasg.utils import swagger_auto_schema
from django.utils import timezone
from .permissions import (
    CsrfExemptMixin,
    HttpDigestRequiredMixin,
    HttpCjdnsAuthorizationRequiredMixin,
)


class DigestTestApiView(HttpDigestRequiredMixin, GenericAPIView):
    """Test Digest Mixin."""

    def get(self, request):
        """GET method."""
        return Response({})

    def post(self, request):
        """GET method."""
        return Response({})


class AuthTestApiView(HttpCjdnsAuthorizationRequiredMixin, GenericAPIView):
    """Test Crypto Auth Mixin."""

    def get(self, request):
        """GET method."""
        return Response({"status": "authorized"})

    def post(self, request):
        """GET method."""
        return Response(request.data)


class RegisterPublicKeyView(CsrfExemptMixin, GenericAPIView):
    """When a new email address is submitted.

    the email address is registered with the system and a unique token
    is generated for that email.
    This token must be kept secret and is used for operations
    related to account management.
    """

    serializer_class = PublicKeyOutputSerializer
    pagination = None

    @swagger_auto_schema(responses={400: 'Invalid request'}, request_body=PublicKeyInputSerializer)
    def post(self, request):
        """Register a new public key.

        Register a new public key. This key is used to verify signatures
        on API endpoints that require authorization. This authorization
        confirms to the draft-cavage-http-signatures-10 Authorization standard.
        """
        print(request.data)
        input_serializer = PublicKeyInputSerializer(data=request.data)
        input_serializer.is_valid(raise_exception=True)
        public_key = input_serializer.save()
        output_serializer = self.get_serializer(public_key)
        # output_serializer.is_valid()
        return Response(output_serializer.data, status.HTTP_201_CREATED)


class CreateAccountApiView(HttpCjdnsAuthorizationRequiredMixin, CsrfExemptMixin, GenericAPIView):
    """When a new email address is submitted.

    the email address is registered with the system and a unique token
    is generated for that email.
    This token must be kept secret and is used for operations
    related to account management.
    """

    serializer_class = UserAccountCreatedSerializer

    @swagger_auto_schema(responses={400: 'Invalid request', 201: UserAccountCreatedSerializer}, request_body=UserEmailSerializer, response_body=UserAccountCreatedSerializer)
    def post(self, request):
        """Register a new email address.

        (REQUIRES AUTHORIZATION). The email address is registered with the system and an email
        is sent to that email with a confirmation link.  The user opens the
        confirmation link, which confirms their registration.
        Meanwhile, the "Check status of new email registration" will reply with
        {"status":"pending"} until the user has opened the confirm URL.
        """
        input_serializer = UserEmailSerializer(data=request.data)
        input_serializer.is_valid(raise_exception=True)
        user = input_serializer.save()
        user.send_account_registration_confirmation_email(request)
        user.account_confirmation_status_url = user.get_account_confirmation_status_url(request)
        output_serializer = self.get_serializer(user)
        return Response(output_serializer.data, status.HTTP_201_CREATED)


class CreateAccountConfirmationStatusApiView(HttpCjdnsAuthorizationRequiredMixin, GenericAPIView):
    """Check on the status of a password reset process."""

    serializer_class = UserAccountConfirmedSerializer

    @swagger_auto_schema(responses={200: UserAccountConfirmedSerializer, 202: UserAccountPendingSerializer, 404: 'Not Found'})
    def get(self, request, client_email):
        """Check status of new email registration.

        (REQUIRES AUTHORIZATION). When a new email address is registered wit the
        "Register a new email address" method, this method responds responds
        with a {"status":"pending"} until the user confirms their email address.
        Once the user confirms their email address, this method returns the
        appSecretToken which can be used to decrypt the wallet
        on the user's app. Once viewed, the password request is destroyed and
        cannot be viewed again.
        """
        user = get_object_or_404(User, email=client_email)
        http_status = status.HTTP_202_ACCEPTED
        output = {'status': 'pending'}
        if user.is_confirmed is True:
            if user.is_app_secret_seen is True:
                http_status = status.HTTP_200_OK
                output = {'status': 'complete'}
            else:
                http_status = status.HTTP_200_OK
                output = {'status': 'complete', 'app_secret_token': user.app_secret_token}
                # for security reasons, disallow access to this app_secret_token in the future
                user.set_app_secret_seen()
        serializer = self.serializer_class(data=output)
        serializer.is_valid()
        return Response(serializer.data, status=http_status)


class CreateResetPasswordRequestApiView(HttpCjdnsAuthorizationRequiredMixin, GenericAPIView):
    """Create a password reset request."""

    serializer_class = PasswordResetInitializationSerializer

    @swagger_auto_schema(responses={200: PasswordResetConfirmedSerializer, 202: PasswordResetPendingSerializer, 404: 'Not Found'})
    def get(self, request, app_secret_token):
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
        password_reset_token = PasswordResetRequest.objects.select_related('user').filter(user__app_secret_token=app_secret_token, expires_on__gt=now).order_by('-created_at').first()
        if password_reset_token is None:
            raise Http404
        http_status = status.HTTP_201_CREATED
        output = {'status': 'pending'}
        if password_reset_token.is_complete is True:
            http_status = status.HTTP_200_OK
            output = {'status': 'complete', 'app_secret_token': password_reset_token.user.app_secret_token}
            # for security reasons, delete any related PasswordResetRequests
            PasswordResetRequest.objects.filter(user__app_secret_token=app_secret_token).delete()
        serializer = PasswordResetConfirmedSerializer(data=output)
        serializer.is_valid()
        return Response(serializer.data, status=http_status)

    @swagger_auto_schema(responses={201: PasswordResetInitializationSerializer, 404: 'Not Found'}, request_body=None)
    def post(self, request, app_secret_token):
        """Initialize a password reset request.

        (REQUIRES AUTHORIZATION). When password registration request is created, the user of
        who owns <app_secret_token> is sent a confirmation email as a
        two factor authentication. The user must confirm their email
        in  order to release the appSecretKey to the VPN app, which
        can be used to decrypt the app wallet and change the password.
        """
        user = get_object_or_404(User, app_secret_token=app_secret_token)
        # for securtiy reasons, delete all previous password reset requests
        PasswordResetRequest.objects.filter(user=user).delete()
        password_reset_token = user.create_password_request()
        password_reset_token.send_password_reset_confirmation_email(request)
        password_reset_token.password_reset_status_url = password_reset_token.get_password_reset_status_url(request)
        serializer = self.serializer_class(password_reset_token)
        return Response(serializer.data, status=status.HTTP_202_ACCEPTED)
