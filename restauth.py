import os
import uuid
import base64
import collections
import logging

import pyramid
from pyramid.security import (authenticated_userid, remember, forget, Everyone,
                                Authenticated)
import pyramid.httpexceptions as exc

from whmac import SignatureException
from message import json, JsonAuthApi, Remotes, AuthException, ClientBad

# Set up logging.
log = logging.getLogger(__name__)


Guest = 'restauth.Guest'
TightGuest = 'restauth.TightGuest'


def ping_view(request):
    """Pyramid view callable to return basic information used to
    tighten the security of the auth.
    """
    data = {'_addr': request.client_addr,
            '_time': int(request.auth_api.time_provider())}

    remote_id = authenticated_userid(request)

    if remote_id:
        sender_id = request.auth_api.sender_id.decode()
        secret = request.auth_api.remotes.get(remote_id.encode())['secret']

        data.update({'remotes': {
                        sender_id: {
                            'senderId': remote_id}}})
    return data


def logout_view(request):
    """Pyramid view callable to log out an authenticated user.
    """
    try:
        forget(request)
        return {}
    except ClientBad:
        raise exc.HTTPForbidden()


class PyramidAuthApi(JsonAuthApi):
    """
    """
    def __init__(self, sender_id, remotes={}, expiry=600, tight_expiry=5):
        """
        """
        JsonAuthApi.__init__(self, sender_id, remotes=Remotes(remotes))
        self.expiry = expiry
        self.tight_expiry = tight_expiry

    def build_client_defaults(self):
        if b'guest' in self.remotes:
            guest = self.remotes.get(b'guest')

            return {'_any': {'secret': guest['secret'].decode(), 'senderId': 'guest'}}
        else:
            return {}

    def parse_sender_id(self, request):
        sender_id = str(request.headers.get('X-Restauth-Sender-Id', ''))

        if sender_id.startswith('*'):
            return sender_id[1:], True
        else:
            return sender_id, False

    def parse_signature(self, request):
        return str(request.headers.get('X-Restauth-Signature', ''))

    def parse_nonce(self, request):
        return str(request.headers.get('X-Restauth-Signature-Nonce', ''))

    def set_sender_id(self, response, sender_id):
        response.headers['X-Restauth-Sender-Id'] = sender_id.decode()

    def set_signature(self, response, signature):
        response.headers['X-Restauth-Signature'] = signature.decode()

    def set_nonce(self, response, nonce):
        response.headers['X-Restauth-Signature-Nonce'] = nonce.decode()

    def send(self, request, response):
        """
        """
        body = response.body.decode('utf-8')
        if body:
            # Prepare some data for signing.
            remote_id, tight = self.parse_sender_id(request)

            try:
                payload = json.loads(body)
            except ValueError:
                payload = {}

            # Invoke the Api.
            try:
                packet = JsonAuthApi.send(self, remote_id.encode(), payload)
            except ClientBad: # Make sure we want this here...
                packet = JsonAuthApi.send(self, b'guest', payload)

            # Add HTTP Headers.
            response.headers['X-Restauth-Signature'] = packet['signature'].decode()
            response.headers['X-Restauth-Signature-Nonce'] = packet['nonce'].decode()
            response.headers['X-Restauth-Sender-Id'] = packet['sender_id'].decode()

    def receive(self, request, default_type=collections.OrderedDict):
        """
        """
        # Get or construct a new payload.
        try:
            payload = json.loads(request.body.decode('utf-8'))
        except ValueError:
            if default_type is dict:
                default_type = collections.OrderedDict
            payload = default_type()

        # Prepare some data for unsigning.
        ip_addr = request.client_addr.encode()
        signature = self.parse_signature(request)
        remote_id, tight = self.parse_sender_id(request)
        nonce = self.parse_nonce(request)
        auth_packet = {'payload': payload, 'signature': signature, 'nonce': nonce, 'sender_id': remote_id}

        if tight:
            print ("tight")
            # Invoke the Api.
            JsonAuthApi.receive(self, auth_packet,
                                ip_addr, expiry=self.tight_expiry)            
        else:
            print ("loose")
            # Try loose receive since tight is not required.
            JsonAuthApi.receive(self, auth_packet, expiry=self.expiry)


class RestAuthnPolicy(PyramidAuthApi):
    """ """

    def __init__(self, *args, **kwa):
        self.authenticated = set()
        PyramidAuthApi.__init__(self, *args, **kwa)

    def remember(self, request, *args):
        """ """
        principal = str(uuid.uuid4())
        secret = base64.b64encode(os.urandom(64))
        
        self.add_remote(principal, {'secret': secret,
                                    'key': None,
                                    'tight': True})
        self.authenticated.add(principal)

        ping_data = ping_view(request)
        ping_data.update({'remotes': {
                            self.sender_id.decode(): {
                                'senderId': principal,
                                'secret': secret.decode()}}})
        return ping_data

    def forget(self, request):
        principal = self.authenticated_userid(request)

        if principal:
            self.remove_remote(principal)
            self.authenticated.remove(principal)
        else:
            raise ClientBad("Remote %s doesn't exist so can't be forgotten")

    def unauthenticated_userid(self, request):
        return self.parse_sender_id(request)[0]

    def authenticated_userid(self, request):
        userid, tight = self.parse_sender_id(request)
        if userid in self.authenticated:
            return userid

    def effective_principals(self, request):
        request.set_property(lambda t: self, 'auth_api')
        remote_id, tight = self.parse_sender_id(request)

        principals = [Everyone]
        request.add_response_callback(self.send)

        try:
            self.receive(request)
        except SignatureException as e:
            log.warn("Tight: Signature failed to verify.")
            return principals + [Guest]
        except AuthException:
            log.warn("Tight: Sender was not authorized.")
            pass
        else:
            if remote_id == 'guest':
                log.info("Tight Guest!")
                return principals + [TightGuest]
            else:
                log.info("Tight Authenticated!")
                return principals + [Authenticated, 
                                'u:%s' % remote_id]

        return principals

        '''
        try:
            self.receive(request, tight=False)
        except SignatureException as e:
            # log.warn("Loose: Signature failed to verify. [%s]" % e)
            pass
        except AuthException:
            # log.warn("Loose: Sender was not authorized.")
            pass
        else:
            request.add_response_callback(self.send)

        '''

