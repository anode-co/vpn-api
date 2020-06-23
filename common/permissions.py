from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.core.exceptions import PermissionDenied
import hashlib
import base64
from rest_framework import permissions
from cjdnsadmin.cjdnsadmin import connect

"""
This tool only works if cjdns is installed and running
Must run the crashey branch to support signatures

Must be connected to at least one peer to create a valid IP lease
Must have a restart loop in /etc/crontab in case cjdns crashes:

* * * * * ps -ef | grep -v grep | grep -v test | grep -q cjdroute || /home/user/cjdns/cjdroute < /etc/cjdroute.conf
"""


class PermissionsPerMethodMixin(object):
    """Grat per-method permissions on a view."""

    def get_permissions(self):
        """Allows overriding default permissions with @permission_classes."""
        view = getattr(self, self.action)
        if hasattr(view, 'permission_classes'):
            return [permission_class() for permission_class in view.permission_classes]
        return super().get_permissions()


class CjdnsMessageSigner:
    """Sign messages using the cjdns signer."""

    CJDNS_IP = '127.0.0.1'
    CJDNS_PORT = 11234
    CJDNS_PASSWORD = "NONE"

    def __init__(self):
        """Initialize the signer."""
        pass

    def sign(self, s, charset):
        """Sign string message using cjdns."""
        s_hash = hashlib.sha256(s.encode(charset)).digest()
        b64_hash = base64.b64encode(s_hash)
        cjdns = connect(self.CJDNS_IP, self.CJDNS_PORT, self.CJDNS_PASSWORD)
        cjdns_result = cjdns.Sign_sign(b64_hash)
        if cjdns_result[b'error'] == b'none':
            encoded_signature = cjdns_result[b'signature']
            signature = encoded_signature.decode('utf-8')
            return signature
        else:
            raise Exception(cjdns_result[b'error'].decode('utf-8'))


class HttpCjdnsAuthorizationVerifier:
    """Verify Cjdns signature."""

    in_verbose_mode = True
    raise_exceptions = True

    AUTH_TYPE = 'cjdns'
    AUTHORIZATION_HEADER = 'Authorization'
    CONTENT_TYPE_HEADER = 'Content-Type'
    REQUIRED_HEADERS = [
        AUTHORIZATION_HEADER,
        CONTENT_TYPE_HEADER,
    ]
    ALGORITHMS_CJDNS = 'cjdns'
    ALGORITHMS = [
        ALGORITHMS_CJDNS,
    ]

    CJDNS_IP = '127.0.0.1'
    CJDNS_PORT = 11234
    CJDNS_PASSWORD = "NONE"

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

    def get_rsa256_b64_message_digest(self, request_body, charset):
        """Create an RSA256 message digest."""
        expected_digest = hashlib.sha256(request_body).digest()
        expected_base64_digest = base64.b64encode(expected_digest).decode(charset)
        return expected_base64_digest

    def is_valid(self, raise_exceptions=True):
        """Dispatch the object."""
        self.say("CHECKING HTTP AUTHORIZATION")
        self.raise_exceptions = raise_exceptions
        request = self.request
        headers = request.headers
        for header in self.REQUIRED_HEADERS:
            if header not in headers:
                message = "Missing header: {}".format(header)
                self.say("  " + message)
                return self.handle_error(PermissionDenied(message))
        try:
            content_type, charset_info = headers[self.CONTENT_TYPE_HEADER].split(";")
        except ValueError:
            message = "Could not read charset info"
            self.say("    " + message)
            charset_info = 'encoding=utf-8'
            # raise PermissionDenied
        charset_title, charset = charset_info.split("=")
        self.say("  charset: {}".format(charset))
        try:
            auth_type, signature = headers[self.AUTHORIZATION_HEADER].split(' ', 1)
        except ValueError:
            message = "Could not retrieve authorization type"
            self.say(message)
            self.say(headers[self.AUTHORIZATION_HEADER])
            return self.handle_error(PermissionDenied(message))
        if auth_type.lower() != self.AUTH_TYPE:
            return self.handle_error(PermissionDenied("Invalid authorization type. \"Signature\" required"))

        self.say("  auth_type: {}".format(auth_type))
        self.say("  auth_info: {}".format(signature))

        # signature = base64.b64decode(base64_signature.encode(charset))

        request_body = request.body
        request_body_digest = self.get_rsa256_b64_message_digest(request_body, charset).encode(charset)
        self.say("  request_body: {}".format(request_body))
        self.say("  request_body_digest: {}".format(request_body_digest))

        cjdns = connect(self.CJDNS_IP, self.CJDNS_PORT, self.CJDNS_PASSWORD)
        cjdns_response = cjdns.Sign_checkSig(
            request_body_digest,
            signature
        )
        print(cjdns_response)
        self.public_key = None
        if cjdns_response[b'error'] == b'none':
            public_key = cjdns_response[b'pubkey'].decode('utf-8')
            self.public_key = public_key
            return True
        else:
            message = "Invalid signature"
            return self.handle_error(PermissionDenied(message))

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


class HttpCjdnsAuthorizationRequiredMixin:
    """Create a Cavage HTTP Authorization Mixin."""

    # should be Signature keyId=<key-id>,algorithm="rsa-sha256",headers="(request-target) date digest",signature=<signature-string>
    in_verbose_mode = True

    def say(self, message):
        """Print debugging messages."""
        if self.in_verbose_mode is True:
            print(message)

    def dispatch(self, request, *args, **kwargs):
        """Dispatch the object."""
        digest_verifier = HttpCjdnsAuthorizationVerifier(request, args, kwargs)
        digest_verifier.is_valid(raise_exceptions=True)
        self.auth_verified_cjdns_public_key = digest_verifier.public_key
        return super().dispatch(request, *args, **kwargs)


class HasHttpCjdnsAuthorization(permissions.BasePermission):
    """Require Cavage-10 crypto-signed authorization at the method level."""

    message = 'HTTP request must be signed with a registered public key'

    def has_permission(self, request, view):
        """Return True if authorization passes signature verification."""
        """Dispatch the object."""
        digest_verifier = HttpCjdnsAuthorizationVerifier(request)
        digest_verifier.is_valid(raise_exceptions=True)
        self.auth_verified_cjdns_public_key = digest_verifier.public_key
        return True


'''
# Test CJDNS hash create

from cjdnsadmin.cjdnsadmin import cjdns
import base64
import json
import hashlib
import requests

cjdns = connect("127.0.0.1", 11234, "NONE")

charset = 'utf-8'
data = {
    "test": "value"
}
data_string = json.dumps(data).encode(charset)
data_string_hash = hashlib.sha256(data_string).digest()
data_string_b64_hash = base64.b64encode(data_string_hash)


output = cjdns.Sign_sign(data_string_b64_hash)

if output[b'error'] == b'none':
    signature = output[b'signature'].decode(charset)

url = 'http://127.0.0.1:8002/api/0.3/tests/auth/'
headers = {
    'Content-Type': 'application/json; encoding=utf-8',
    'Authorization': 'cjdns {}'.format(signature)
}
response = requests.post(url, json=data, headers=headers)

Sign_sign("yabba-dabba-doooo")'
{
  "error": "none",
  "signature": "0ytl2njc1hy86tlxtc2zc3449up47uqb0u04kcy233d7zrn2cwh1_1ggrny99st550czt4x84cqpgtr0g0fguq3q7jcyry9nlbjrg9hxg9006s034gp5grnundwkp48dbysb154zln18ym28tnwh9t1qjq40",
  "txid": "801605211"
}


'''

'''
# Shortcut function for testing signatures


from cjdnsadmin.cjdnsadmin import connect
import base64
import json
import hashlib
import requests
from django.utils import timezone


charset = 'utf-8'
data = {
    'date': round(timezone.now().timestamp())
}


def secure_request(url, method, data):
    charset = 'utf-8'
    cjdns = connect("127.0.0.1", 11234, "NONE")
    if data is None:
        data_string = ''.encode('utf-8')
    else:
        data_string = json.dumps(data, separators=(',', ':')).encode(charset)
    data_string_hash = hashlib.sha256(data_string).digest()
    data_string_b64_hash = base64.b64encode(data_string_hash)
    print("base64_hash: {}".format(data_string_b64_hash))
    output = cjdns.Sign_sign(data_string_b64_hash)
    print(output)
    if output[b'error'] == b'none':
        signature = output[b'signature'].decode(charset)
    headers = {
        'Content-Type': 'application/json; encoding=utf-8',
        'Authorization': 'cjdns {}'.format(signature)
    }
    response = requests.request(method, url=url, data=data_string, headers=headers)
    return response


login_url = 'http://127.0.0.1:8002/api/0.3/vpn/accounts/'
login_method = 'post'
login_data = {'username': 'dimitris'}
login_response = secure_request(login_url, login_method, login_data)


email_url = 'http://127.0.0.1:8002/api/0.3/vpn/accounts/dimitris/initialemail/'
email_method = 'post'
email_data = {'email': 'backupbrain@gmail.com'}
email_response = secure_request(email_url, email_method, email_data)


'''
