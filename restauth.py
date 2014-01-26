import os
import time
import base64
import hashlib
import collections
import functools
import logging

from whmac import SignatureException
from message import json, JsonAuthApi, Remotes, AuthException

# Set up logging.
log = logging.getLogger(__name__)


# Main Api
# ========
class PyramidAuthApi(JsonAuthApi):
    """
    """
    def __init__(self, sender_id, remotes={}, expiry=600, tight_expiry=5):
        """
        """
        JsonAuthApi.__init__(self, sender_id, remotes=Remotes(remotes))
        self.expiry = expiry
        self.tight_expiry = tight_expiry
        
    def parse_sender_id(self, request):
        return str(request.headers.get('X-Restauth-Sender-Id', ''))

    def parse_signature(self, request):
        return str(request.headers.get('X-Restauth-Signature', ''))

    def parse_nonce(self, request):
        return str(request.headers.get('X-Restauth-Signature-Nonce', ''))

    def send(self, request, response):
        """
        """
        body = response.body.decode('utf-8')
        if body:
            # Prepare some data for signing.
            remote_id = self.parse_sender_id(request)

            payload = json.loads(body)

            # Invoke the Api.
            packet = JsonAuthApi.send(self, remote_id.encode(), payload)

            # Add HTTP Headers.
            response.headers['X-Restauth-Signature'] = packet['signature'].decode()
            response.headers['X-Restauth-Signature-Nonce'] = packet['nonce'].decode()
            response.headers['X-Restauth-Sender-Id'] = packet['sender_id'].decode()

    def receive(self, request, tight=True,
                    default_type=collections.OrderedDict):
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
        signature = self.parse_signature(request)
        remote_id = self.parse_sender_id(request)
        nonce = self.parse_nonce(request)
        auth_packet = {'payload': payload, 'signature': signature, 'nonce': nonce, 'sender_id': remote_id}

        def try_tight():
            # Invoke the Api.
            JsonAuthApi.receive(self, auth_packet,
                                request.client_addr.encode(), expiry=self.tight_expiry)            

        if tight:
            try_tight()
        else:
            try:
                # Try loose receive since tight is not required.
                JsonAuthApi.receive(self, auth_packet, expiry=self.expiry)
            except SignatureException:
                print ("trying tight ")
                # Now just run a tight receive in case those params
                #   were hashed on the client. Though, this shouldn't happen.
                try_tight()


# Pyramid Stuff
# =============
try:
    import pyramid
except ImportError:
    log.info("Pyramid is unavailable. You won't be able to use "
                "`auth_view_config`")
else:
    from pyramid.security import Everyone, Authenticated
    from pyramid.view import view_config

    import pyramid.httpexceptions as exc
    from pyramid.security import authenticated_userid

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
            secret = request.auth_api.remotes.get(remote_id.encode())[0]

            data.update({'remotes': {
                            sender_id: {
                                'senderId': remote_id}}})
                                #'secret': secret}}})

        return data


    class RestAuthHelper(PyramidAuthApi):
        def add_client(self, client_id, secret):
            self.remotes.update(client_id.encode(), (secret, ''))


    class RestAuthnPolicy(object):
        """ """

        def __init__(self, *args, **kwa):
            self.helper = RestAuthHelper(*args, **kwa)
            self.authenticated = set()

        def remember(self, request, principal, **kw):
            #print(**kw)
            print (principal)
            self.helper.add_client(principal, kw['secret'])
            self.authenticated.add(principal)

        def forget(self, request):
            print ("FORGET ME!")

        def unauthenticated_userid(self, request):
            return self.helper.parse_sender_id(request)

        def authenticated_userid(self, request):
            userid = self.helper.parse_sender_id(request)
            if userid in self.authenticated:
                return userid

        def effective_principals(self, request):
            request.set_property(lambda t: self.helper, 'auth_api')
            remote_id = self.helper.parse_sender_id(request)

            try:
                self.helper.receive(request, tight=False)
            except SignatureException as e:
                log.warn("Loose: Signature failed to verify. [%s]" % e)
                return [Everyone]
            except AuthException:
                log.warn("Loose: Sender was not authorized.")
                return [Everyone]
            else:
                request.add_response_callback(self.helper.send)

                try:
                    self.helper.receive(request, tight=True)
                except SignatureException as e:
                    log.warn("Tight: Signature failed to verify.")
                    return [Everyone, Guest]
                except AuthException:
                    log.warn("Tight: Sender was not authorized.")
                    return [Everyone]
                else:
                    print (remote_id)
                    if remote_id == 'guest':
                        log.info("Tight Guest!")
                        return [Everyone, TightGuest]
                    else:
                        log.info("Tight Authenticated!")
                        return [Everyone, Authenticated, 
                                        'u:%s' % remote_id]