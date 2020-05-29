from rest_framework.generics import GenericAPIView
from rest_framework.decorators import action, permission_classes  # other imports elided
from rest_framework.response import Response
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from rest_framework import status
from django.shortcuts import get_object_or_404
from .models import (
    User,
    PasswordResetToken,
    PublicKey
)
from .serializers_0_3 import (
    UserEmailSerializer,
    UserPublicKeySerializer,
    GenericResponseSerializer,
    PasswordResetTokenSerializer,
    PublicKeyInputSerializer,
    PublicKeyOutputSerializer,
)
from drf_yasg.utils import swagger_auto_schema
from django.core.exceptions import PermissionDenied, SuspiciousOperation
import hashlib
import base64
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from fastecdsa import curve, ecdsa, keys
from fastecdsa.encoding import pem


class CsrfExemptMixin(object):
    """Create a CSRF Excempt mixin."""

    @method_decorator(csrf_exempt)
    def dispatch(self, *args, **kwargs):
        """Dispatch the object."""
        return super(CsrfExemptMixin, self).dispatch(*args, **kwargs)


class HttpDigestRequiredMixin:
    """Force a Digest: header."""

    # should be like SHA-256=2ajR8Q+lBNm0eQW9DWWX8dZDZLB8+h0Rgmu0UCDdFrw=
    is_verbose = True

    DIGEST_HEADER = 'Digest'
    CONTENT_TYPE_HEADER = 'Content-Type'
    REQUIRED_HEADERS = [
        DIGEST_HEADER,
        CONTENT_TYPE_HEADER
    ]

    def say(self, message):
        """Print debugging messages."""
        if self.in_verbose_mode is True:
            print(message)

    def dispatch(self, request, *args, **kwargs):
        """Dispatch the object."""
        self.say("CHECKING HTTP DIGEST")
        headers = request.headers
        for header in self.REQUIRED_HEADERS:
            if header not in headers:
                self.say("  missing header: {}".format(header))
                raise SuspiciousOperation
        try:
            content_type, charset_info = headers[self.CONTENT_TYPE_HEADER].split(";")
        except ValueError:
            self.say("    could not read charset info")
            charset_info = 'encoding=utf-8'
            # raise SuspiciousOperation
        charset_title, charset = charset_info.split("=")
        self.say("  charset: {}".format(charset))
        try:
            digest_algorithm, base64_digest = headers[self.DIGEST_HEADER].split("=", 1)
        except ValueError:
            raise SuspiciousOperation
        self.say("  digest algorithm: {}".format(digest_algorithm))
        self.say("  b64 encoded digest: {}".format(base64_digest))
        try:
            digest = base64.b64decode(base64_digest.encode(charset)).decode(charset)
        except LookupError:
            raise SuspiciousOperation
        self.say("  digest: {}".format(digest))
        request_body = request.body
        self.say("  requset body: {}".format(request_body))
        if digest_algorithm == 'SHA-512':
            test_digest = hashlib.sha512(request_body).hexdigest()
        elif digest_algorithm == 'SHA-384':
            test_digest = hashlib.sha384(request_body).hexdigest()
        elif digest_algorithm == 'SHA-256':
            test_digest = hashlib.sha256(request_body).hexdigest()
        elif digest_algorithm == 'SHA-1':
            test_digest = hashlib.sha1(request_body).hexdigest()
        elif digest_algorithm == 'MD5':
            test_digest = hashlib.md5(request_body).hexdigest()
        else:
            self.say("  No algorithm found.")
            raise SuspiciousOperation
        self.say("  message digest: {}".format(test_digest))
        if test_digest != digest:
            self.say("  digests MISMATCH!")
            raise SuspiciousOperation
        self.say("  digests match!")
        return super().dispatch(request, *args, **kwargs)


class DigestTestApiView(HttpDigestRequiredMixin, GenericAPIView):
    """Test Digest Mixin."""

    def get(self, request):
        """GET method."""
        return Response({})

    def post(self, request):
        """GET method."""
        return Response({})


'''
    if (hash == "SHA-512"):
        digest = SHA512.new()
    elif (hash == "SHA-384"):
        digest = SHA384.new()
    elif (hash == "SHA-256"):
        digest = SHA256.new()
    elif (hash == "SHA-1"):
        digest = SHA.new()
    else:
        digest = MD5.new()
    digest.update(message)

        body = request.body
'''


class HttpCrypoAuthorizationRequiredMixin:
    """Create a Cavage HTTP Authorization Mixin."""

    # should be Signature keyId=<key-id>,algorithm="rsa-sha256",headers="(request-target) date digest",signature=<signature-string>
    in_verbose_mode = False

    AUTH_TYPE = 'signature'
    AUTHORIZATION_HEADER = 'Authorization'
    CONTENT_TYPE_HEADER = 'Content-Type'
    REQUIRED_HEADERS = [
        AUTHORIZATION_HEADER,
        CONTENT_TYPE_HEADER,
    ]
    ALGORITHMS_ECDSA_P256 = 'edca-p256'
    ALGORITHMS_ECDSA_CURVE25519 = 'edca-curve25519'
    ALGORITHMS_RSA_SHA256 = 'rsa-sha256'
    ALGORITHMS = [
        ALGORITHMS_ECDSA_P256,
        ALGORITHMS_ECDSA_CURVE25519,
        ALGORITHMS_RSA_SHA256
    ]
    ALGORITHMS_FASTECDSA = [
        ALGORITHMS_ECDSA_P256,
        ALGORITHMS_ECDSA_CURVE25519
    ]
    ALGORITHMS_CRYTPO = [
        ALGORITHMS_RSA_SHA256,
    ]

    def say(self, message):
        """Print debugging messages."""
        if self.in_verbose_mode is True:
            print(message)

    def dispatch(self, request, *args, **kwargs):
        """Dispatch the object."""
        self.say("CHECKING HTTP AUTHORIZATION")
        headers = request.headers
        for header in self.REQUIRED_HEADERS:
            if header not in headers:
                self.say("  missing header: {}".format(header))
                raise SuspiciousOperation
        try:
            content_type, charset_info = headers[self.CONTENT_TYPE_HEADER].split(";")
        except ValueError:
            self.say("    could not read charset info")
            charset_info = 'encoding=utf-8'
            # raise SuspiciousOperation
        charset_title, charset = charset_info.split("=")
        self.say("  charset: {}".format(charset))
        try:
            auth_type, auth_info = headers[self.AUTHORIZATION_HEADER].split(' ', 1)
        except ValueError:
            raise SuspiciousOperation
        if auth_type.lower() != self.AUTH_TYPE:
            raise SuspiciousOperation

        self.say("  auth_type: {}".format(auth_type))
        self.say("  auth_info: {}".format(auth_info))

        try:
            auth_info_keypairs = auth_info.split(',')
        except ValueError:
            raise SuspiciousOperation
        auth_infos = {}
        for auth_info_keypair in auth_info_keypairs:
            key, value = auth_info_keypair.split("=", 1)
            if value[0] == '"' and value[-1] == '"':
                value = value[1:-1]
            auth_infos[key] = value
            self.say("    {}: {}".format(key, value))

        # TODO: implement 'header' checks
        # must throw errors in certain conditions
        # https://tools.ietf.org/html/draft-cavage-http-signatures-12

        if 'keyId' not in auth_infos:
            raise SuspiciousOperation
        public_key_id = auth_infos['keyId']

        if 'algorithm' not in auth_infos:
            raise SuspiciousOperation
        algorithm = auth_infos['algorithm']

        if 'signature' not in auth_infos:
            raise SuspiciousOperation
        base64_signature = auth_infos['signature']
        try:
            signature = base64.b64decode(base64_signature.encode(charset))
        except LookupError:
            self.say("Could not decode base64 signature")
            raise SuspiciousOperation
        self.say("  signature: {}".format(signature))

        try:
            public_key = PublicKey.objects.get(public_key_id=public_key_id)
            self.say("  raw public key: '{}'".format(public_key.public_key))
        except PublicKey.DoesNotExist:
            self.say("Could not import RSA key")
            raise PermissionDenied

        self.say(request)
        self.say(request.headers)
        self.say(request.body)
        request_body = request.body
        self.say("  request_body: {}".format(request_body))

        if algorithm not in self.ALGORITHMS:
            self.say("  algorithm not found")
            raise PermissionDenied

        if algorithm in self.ALGORITHMS_FASTECDSA:
            # is_valid = ecdsa.verify((r, s), m, public_key)
            self.say("  public key: {}".format(public_key.public_key))
            # ecdsa_public_key = pem.PEMEncoder.decode_public_key('-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----'.format(public_key.public_key))
            ecdsa_public_key = pem.PEMEncoder.decode_public_key(public_key.public_key)
            self.say("  loaded public key")
            signature_length = len(signature)
            self.say("  signature length: {} bytes".format(signature_length))
            r_bytes, s_bytes = signature[:signature_length // 2], signature[signature_length // 2:signature_length]
            self.say("  split signature into two parts")
            r, s = int.from_bytes(r_bytes, 'big', signed=False), int.from_bytes(s_bytes, 'big', signed=False)
            self.say("      r: {}".format(r))
            self.say("      s: {}".format(s))

            curve_algorithm = None
            if algorithm == self.ALGORITHMS_ECDSA_P256:
                curve_algorithm = curve.P256
            elif algorithm == self.ALGORITHMS_ECDSA_CURVE25519:
                curve_algorithm = curve.W25519

            is_valid = ecdsa.verify((r, s), request_body, ecdsa_public_key, curve=curve_algorithm)
            if is_valid is True:
                self.say("  -- AUTHORIZED  -- ")
                return super().dispatch(request, *args, **kwargs)
            else:
                self.say("  Could not verify signature")
                raise SuspiciousOperation

        elif algorithm in self.ALGORITHMS_CRYTPO:
            try:
                rsa_public_key = RSA.import_key(public_key.public_key)
                self.say("exported public key: {}".format(rsa_public_key.export_key().decode('utf-8')))
            except Exception:
                raise PermissionDenied
            signer = PKCS1_v1_5.new(rsa_public_key)

            self.say("  public_key: {}".format(rsa_public_key))

            if algorithm == self.ALGORITHMS_RSA_SHA256:
                self.say("  algorithm: SHA256")
                digest = SHA256.new()

            digest.update(request_body)
            if signer.verify(digest, signature) is False:
                self.say("Could not verify signature")
                raise PermissionDenied

            self.say("  -- AUTHORIZED  -- ")
            return super().dispatch(request, *args, **kwargs)
        else:
            self.say("  algorithm nos supported")
            raise SuspiciousOperation

        '''

        if signature_algorithm != 'ecdsa-sha256':
            raise SuspiciousOperation
        signature = auth_infos['signature']


        '''
        '''
        message = request.body
        valid = ecdsa.verify((r, s), message, public_key, curve=curve.P224)
        '''


'''
# Test registration with RSA SHA512
import requests
from Crypto import Random
from Crypto.PublicKey import RSA

charset = 'utf-8'

random_generator = Random.new().read
keysize = 2048
private_key = RSA.generate(keysize, random_generator)
public_key = private_key.publickey().decode(charset)

public_key_string = public_key.export_key().decode(charset)
algorithm = 'rsa-sha256'
payload = {
    'public_key': public_key_string,
    'algorithm': algorithm
}
headers = {
    'Content-Type': 'application/json; encoding="{}"'.format(charset)
}
response = requests.post(url, json=payload, headers=headers)

public_key_id = response.json()['publicKeyId']
'''

'''
# Test registration with Elliptic Curve
import requests
from fastecdsa.keys import export_key
from fastecdsa import keys, curve
# https://github.com/AntonKueltz/fastecdsa

url = 'http://127.0.0.1:8002/api/0.3/vpn/clients/publickeys/'
private_key, public_key = keys.gen_keypair(curve.W25519)  # .P256
public_key_string = export_key(public_key, curve.W25519)  # .P256
algorithm = 'ecdsa-curve25519'  # -p256
public_key_data = {
    'public_key': public_key_string,
    'algorithm': algorithm
}
response = requests.post(url, json=public_key_data)

public_key_id = response.json()['publicKeyId']
'''

'''
# TEST the authenticator with SHA512
import requests
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA512, SHA384, SHA256
import base64
import json

charset = 'utf-8'

# random_generator = Random.new().read
# keysize = 2048
# private_key = RSA.generate(keysize, random_generator)
# public_key = private_key.publickey()
# public_key_string = public_key.export_key().decode(charset)
# algorithm = 'rsa-sha256'

data = {
    "test": "value"
}
data_string = json.dumps(data).encode(charset)

signer = PKCS1_v1_5.new(private_key)
digest = SHA256.new()
digest.update(data_string)
signature = signer.sign(digest)
base64_signature = base64.b64encode(signature).decode('utf-8')

headers = {
    'Content-Type': 'application/json; encoding="{}"'.format(charset),
    'Authorization': 'Signature keyId={},algorithm="{}",signature={}'.format(
        public_key_id,
        algorithm,
        base64_signature
    )
}

url = 'http://127.0.0.1:8002/api/0.3/tests/auth/'

response = requests.post(url, data=data_string, headers=headers)

'''


'''
# TEST the authenticator with Elliptic Curve

import base64
from fastecdsa import curve, ecdsa, keys
from fastecdsa.encoding import pem
import requests

encoding = 'utf-8'
url = 'http://127.0.0.1:8002/api/0.3/tests/auth/'
keyId = 'MFkwEwYHKo-2'
payload = 'Hello'
algorithm = 'ecdsa-w22519'



headers = {
    'Content-Type': 'text/plain; encoding="{}"'.format(encoding),
    'Authorization': 'Signature keyId={},algorithm="{}",signature={}'.format(key_id, algorithm, base64_signature_edcsa)

}
response = requests.post(url, data=payload, headers=headers)
'''


'''

--H Date: <req-date>
-H Digest: SHA-256=2ajR8Q+lBNm0eQW9DWWX8dZDZLB8+h0Rgmu0UCDdFrw=
-H Authorization: Signature keyId=<key-id>,algorithm="rsa-sha256",headers="(request-target) date digest",signature=<signature-string>
-H Content-Type: application/x-www-form-urlencoded
-d grant_type=client_credentials&scope=scope1
'''
'''
def verify(message, signature, pub_key):
    signer = PKCS1_v1_5.new(pub_key)
    if (hash == "SHA-512"):
        digest = SHA512.new()
    elif (hash == "SHA-384"):
        digest = SHA384.new()
    elif (hash == "SHA-256"):
        digest = SHA256.new()
    elif (hash == "SHA-1"):
        digest = SHA.new()
    else:
        digest = MD5.new()
    digest.update(message)
    return signer.verify(digest, signature)
        if Product.objects.filter(pk=1, activate=True):
            return super().dispatch(request, *args, **kwargs)
        else:
            raise PermissionDenied
'''


class AuthTestApiView(HttpCrypoAuthorizationRequiredMixin, GenericAPIView):
    """Test Crypto Auth Mixin."""

    def get(self, request):
        """GET method."""
        return Response({})

    def post(self, request):
        """GET method."""
        return Response({})


class RegisterPublicKeyView(CsrfExemptMixin, GenericAPIView):
    """When a new email address is submitted.

    the email address is registered with the system and a unique token
    is generated for that email.
    This token must be kept secret and is used for operations
    related to account management.
    """

    serializer_class = PublicKeyOutputSerializer

    @swagger_auto_schema(responses={400: 'Invalid request'}, request_body=PublicKeyInputSerializer)
    def post(self, request):
        """When a new email address is submitted.

        The email address is registered with the system and a unique token
        is generated for that email.
        This token must be kept secret and is used for operations
        related to account management.
        """
        input_serializer = PublicKeyInputSerializer(data=request.data)
        input_serializer.is_valid(raise_exception=True)
        public_key = input_serializer.save()
        output_serializer = self.get_serializer(public_key)
        # output_serializer.is_valid()
        return Response(output_serializer.data, status.HTTP_201_CREATED)


class CreateAccountApiView(CsrfExemptMixin, GenericAPIView):
    """When a new email address is submitted.

    the email address is registered with the system and a unique token
    is generated for that email.
    This token must be kept secret and is used for operations
    related to account management.
    """

    serializer_class = UserPublicKeySerializer

    @swagger_auto_schema(responses={400: 'Invalid request'}, request_body=UserEmailSerializer)
    def post(self, request):
        """When a new email address is submitted.

        The email address is registered with the system and a unique token
        is generated for that email.
        This token must be kept secret and is used for operations
        related to account management.
        """
        input_serializer = UserEmailSerializer(data=request.data)
        input_serializer.is_valid(raise_exception=True)
        user = input_serializer.save()
        output_serializer = self.get_serializer(user)
        return Response(output_serializer.data, status.HTTP_201_CREATED)


class CreateResetPasswordRequestApiView(GenericAPIView):
    """Create a password reset request."""

    serializer_class = PasswordResetTokenSerializer

    @swagger_auto_schema(responses={404: 'Not Found'})
    def post(self, request, client_email):
        """."""
        user = get_object_or_404(User, email=client_email)
        PasswordResetToken.objects.filter(user=user).delete()
        password_reset_token = user.create_password_request()
        password_reset_token.send_password_reset_confirmation_email(request)
        password_reset_token.password_reset_status_url = password_reset_token.get_password_reset_status_url(request)
        serializer = self.serializer_class(password_reset_token)
        return Response(serializer.data, status=status.HTTP_202_ACCEPTED)


class ResetPasswordConfirmationStatusApiView(GenericAPIView):
    """Check on the status of a password reset process."""

    serializer_class = GenericResponseSerializer

    @swagger_auto_schema(responses={200: 'Ok', 202: 'Accepted', 404: 'Not Found'})
    def get(self, request, client_email, password_reset_token):
        """Check on the status of a password reset confirmation."""
        print(client_email)
        print(password_reset_token)
        session_token = get_object_or_404(PasswordResetToken, password_reset_token=password_reset_token, user__email=client_email)
        http_status = status.HTTP_202_ACCEPTED
        output = {'status': 'pending'}
        if session_token.is_complete is True:
            http_status = status.HTTP_200_OK
            output = {'status': 'complete'}
        serializer = self.serializer_class(data=output)
        serializer.is_valid()
        return Response(serializer.data, status=http_status)
