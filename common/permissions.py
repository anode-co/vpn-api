from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.core.exceptions import PermissionDenied, SuspiciousOperation
import hashlib
import base64
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from fastecdsa import curve, ecdsa
from fastecdsa.encoding import pem
from .models import PublicKey
from rest_framework import permissions


class HttpDigestVerifier:
    """Verify HTTP signatures."""

    in_verbose_mode = True
    raise_exceptions = True

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

    def __init__(self, request, *args, **kwargs):
        """Initialize class."""
        self.say("In verbose mode")
        self.request = request
        self.args = args
        self.kwargs = kwargs

    def handle_error(self, exception_type):
        """Return False or raise exception."""
        if self.raise_exceptions is True:
            raise exception_type
        else:
            return False

    def is_valid(self, raise_exceptions=True):
        """Dispatch the object."""
        self.say("CHECKING HTTP AUTHORIZATION")
        self.raise_exceptions = raise_exceptions
        request = self.request
        headers = request.headers
        print(headers)
        print('meta:')
        print(request.META)
        for header in self.REQUIRED_HEADERS:
            if header not in headers:
                message = "Missing header: {}".format(header)
                self.say("  " + message)
                return self.handle_error(SuspiciousOperation(message))
        try:
            content_type, charset_info = headers[self.CONTENT_TYPE_HEADER].split(";")
        except ValueError:
            message = "Could not read charset info"
            self.say("    " + message)
            charset_info = 'encoding=utf-8'
            # raise SuspiciousOperation
        charset_title, charset = charset_info.split("=")
        self.say("  charset: {}".format(charset))
        try:
            auth_type, auth_info = headers[self.AUTHORIZATION_HEADER].split(' ', 1)
        except ValueError:
            message = "Could not retrieve authorization type"
            self.say(message)
            self.say(headers[self.AUTHORIZATION_HEADER])
            return self.handle_error(SuspiciousOperation(message))
        if auth_type.lower() != self.AUTH_TYPE:
            return self.handle_error(SuspiciousOperation("Invalid authorization type. \"Signature\" required"))

        self.say("  auth_type: {}".format(auth_type))
        self.say("  auth_info: {}".format(auth_info))

        try:
            auth_info_keypairs = auth_info.split(',')
        except ValueError:
            return self.handle_error(SuspiciousOperation("Invalid authorization key parameters"))
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
            return self.handle_error(SuspiciousOperation("No keyId psecified"))
        public_key_id = auth_infos['keyId']

        if 'algorithm' not in auth_infos:
            return self.handle_error(SuspiciousOperation("No algorithm specified"))
        algorithm = auth_infos['algorithm']

        if 'signature' not in auth_infos:
            return self.handle_error(SuspiciousOperation("No signature specified"))
        base64_signature = auth_infos['signature']
        try:
            signature = base64.b64decode(base64_signature.encode(charset))
        except LookupError:
            self.say("Could not decode base64 signature")
            return self.handle_error(SuspiciousOperation("signature could not be base64 decoded"))
        self.say("  signature: {}".format(signature))

        try:
            public_key = PublicKey.objects.get(public_key_id=public_key_id)
            self.say("  raw public key: '{}'".format(public_key.public_key))
        except PublicKey.DoesNotExist:
            self.say("Could not import RSA key")
            return self.handle_error(PermissionDenied)

        self.say(request)
        self.say(request.headers)
        self.say(request.body)
        request_body = request.body
        self.say("  request_body: {}".format(request_body))

        if algorithm not in self.ALGORITHMS:
            self.say("  algorithm not found")
            if self.raise_exceptions is True:
                return self.handle_error(PermissionDenied)
            return False

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
                return True
            else:
                message = "Could not verify signature"
                self.say("  " + message)
                return self.handle_error(SuspiciousOperation(message))

        elif algorithm in self.ALGORITHMS_CRYTPO:
            try:
                public_key_string = public_key.public_key
                # Add  \n every 64 characters if they don't exist
                if (public_key_string[91] != '\n'):
                    public_key_string = public_key_string[27:-25]
                    block_length = 64
                    public_key_string = '-----BEGIN PUBLIC KEY-----\n' + '\n'.join(public_key_string[i:i + block_length] for i in range(0, len(public_key_string), block_length)) + '\n-----END PUBLIC KEY-----'
                rsa_public_key = RSA.importKey(public_key_string)
                self.say("exported public key: {}".format(rsa_public_key.exportKey().decode('utf-8')))
            except Exception:
                return self.handle_error(PermissionDenied)
            signer = PKCS1_v1_5.new(rsa_public_key)

            self.say("  public_key: {}".format(rsa_public_key))

            if algorithm == self.ALGORITHMS_RSA_SHA256:
                self.say("  algorithm: SHA256")
                digest = SHA256.new()

            digest.update(request_body)
            if signer.verify(digest, signature) is False:
                self.say("Could not verify signature")
                return self.handle_error(PermissionDenied)

            self.say("  -- AUTHORIZED  -- ")
            return True
        else:
            message = "Algorithm not  supported"
            self.say("  " + message)
            return self.handle_error(SuspiciousOperation(message))
        return True

    def say(self, message):
        """Print debugging messages."""
        if self.in_verbose_mode is True:
            print(message)


class CsrfExemptMixin(object):
    """Create a CSRF Excempt mixin."""

    @method_decorator(csrf_exempt)
    def dispatch(self, *args, **kwargs):
        """Dispatch the object."""
        return super(CsrfExemptMixin, self).dispatch(*args, **kwargs)


class HttpDigestRequiredMixin:
    """Force a Digest: header."""

    # should be like SHA-256=2ajR8Q+lBNm0eQW9DWWX8dZDZLB8+h0Rgmu0UCDdFrw=
    in_verbose_mode = True

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
    in_verbose_mode = True

    def say(self, message):
        """Print debugging messages."""
        if self.in_verbose_mode is True:
            print(message)

    def dispatch(self, request, *args, **kwargs):
        """Dispatch the object."""
        digest_verifier = HttpDigestVerifier(request, args, kwargs)
        digest_verifier.is_valid(raise_exceptions=True)
        return super().dispatch(request, *args, **kwargs)

        '''

        if signature_algorithm != 'ecdsa-sha256':
            raise SuspiciousOperation
        signature = auth_infos['signature']


        '''
        '''
        message = request.body
        valid = ecdsa.verify((r, s), message, public_key, curve=curve.P224)
        '''


class HasHttpCrypoAuthorization(permissions.BasePermission):
    """Require Cavage-10 crypto-signed authorization at the method level."""

    message = 'HTTP request must be signed with a registered public key'

    def has_permission(self, request, view):
        """Return True if authorization passes signature verification."""
        """Dispatch the object."""
        digest_verifier = HttpDigestVerifier(request)
        digest_verifier.is_valid(raise_exceptions=True)
        return True


'''
# Test registration with RSA SHA512
import requests
from Crypto import Random
from Crypto.PublicKey import RSA

charset = 'utf-8'

random_generator = Random.new().read
keysize = 2048
private_key = RSA.generate(keysize, random_generator)
public_key = private_key.publickey()

public_key_string = public_key.export_key().decode(charset)
algorithm = 'rsa-sha256'
url = 'http://127.0.0.1:8002/api/0.3/vpn/clients/publickeys/'
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
