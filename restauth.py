import time
import json
import base64
import hmac
import hashlib
import collections
import functools
import logging


# Set up logging.
log = logging.getLogger(__name__)


# Provides consistency for serialization/hashing.
json_dumps = functools.partial(json.dumps, separators=(',', ':'))
json_loads = functools.partial(json.loads,
                                object_pairs_hook=collections.OrderedDict)


# Exceptions
# ==========
class AuthException(Exception):
    pass


class SignatureBad(AuthException):
    pass


class ClientBad(AuthException):
    pass


class SignatureTimeout(AuthException):
    pass


# Main Api
# ========
class AuthApi(object):
    """
    """
    def __init__(self, sender_id, remotes={}, passes=100, threshold=600,
                    time_provider=time.time):
        """
        """
        self.sender_id = sender_id
        self.remotes = remotes
        self.passes = passes
        self.threshold = threshold
        self.time_provider = time_provider

    def sign(self, *args):
        """Tighter HMAC-SHA256 that uses the UTC timestamp and multiple
        passes.
        """
        h = hmac.new(args[0].encode(), None, hashlib.sha256)
        for i in range(self.passes):
            for arg in args:
                h.update(arg.encode())            
        return base64.b64encode(h.digest()).decode(encoding='utf-8')

    def unsign(self, secret, timestamp, signature, *args, **kwa):
        """
        """
        threshold = kwa.get('threshold', self.threshold) * 1000

        timestamp = int(timestamp)
        utcnow = int(self.time_provider())
        delta = utcnow - timestamp;
        if abs(delta) > threshold:
            raise SignatureTimeout("Signature it too old. %s:%s" %
                                    (utcnow, timestamp))
        challenge = self.sign(secret, str(timestamp), *args)
        if signature != challenge:
            raise SignatureBad("Incorrect HMAC challenge. %s:%s" %
                                (signature, challenge))

    def send(self, remote_id, payload, *args):
        """
        """
        secret = self.remotes[remote_id]
        now = int(self.time_provider())

        payload = json_dumps(payload)
        now = json_dumps(now)

        return (self.sign(secret, now, payload, self.sender_id ,*args), now)

    def receive(self, remote_id, timestamp, signature, payload, *args, **kwa):
        """
        """
        if not remote_id in self.remotes:
            raise ClientBad("Remote id %s is not a valid client." % remote_id)

        payload = json_dumps(payload)
        secret = self.remotes[remote_id]

        self.unsign(secret, timestamp, signature, payload, remote_id, *args, **kwa)


class PyramidAuthApiServer(AuthApi):
    """
    """
    def __init__(self, sender_id, remotes={}, passes=100, threshold=600,
                    tight_threshold=15, time_provider=time.time,
                    header_signature='', header_timestamp='',
                    header_remoteid=''):
        """
        """
        AuthApi.__init__(self, sender_id, remotes, passes, threshold, time.time)
        self.tight_threshold = tight_threshold
        self.header_signature = header_signature or 'X-Signature'
        self.header_timestamp = header_timestamp or 'X-Signature-Timestamp'
        self.header_remoteid = header_remoteid or 'X-Client-Id'

    def send(self, request, response):
        """
        """
        body = response.body.decode('utf-8')
        if body:
            # Prepare some data for signing.
            remote_id = str(request.headers.get(self.header_remoteid, ''))

            payload = json_loads(body)
        
            # Invoke the Api.
            sig, now = AuthApi.send(self, remote_id, payload)

            # Add HTTP Headers.
            response.headers[self.header_signature] = sig
            response.headers[self.header_timestamp] = now
            response.headers[self.header_remoteid] = self.sender_id

    def receive(self, request, tight=True,
                    default_type=collections.OrderedDict):
        """
        """
        # Get or construct a new payload.
        try:
            payload = json_loads(request.body.decode('utf-8'))
        except ValueError:
            if default_type is dict:
                default_type = collections.OrderedDict
            payload = default_type()

        # Prepare some data for unsigning. 
        signature = str(request.headers.get(self.header_signature, ''))
        timestamp = int(request.headers.get(self.header_timestamp, 0))
        remote_id = str(request.headers.get(self.header_remoteid, ''))

        def try_tight():
            args = (request.client_addr,)
            kwa = {'threshold': self.tight_threshold}
            # Invoke the Api.
            AuthApi.receive(self, remote_id, timestamp, signature, payload, *args, **kwa)            

        if tight:
            try_tight()
        else:
            args = ()
            kwa = {}
            try:
                # Try loose receive since tight is not required.
                AuthApi.receive(self, remote_id, timestamp, signature, payload, *args, **kwa)
            except AuthException:
                # Now just run a tight receive in case those params were sent on the client.
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

        client_id = authenticated_userid(request);

        if client_id:
           data['clientId'] = client_id

        return data


    class RestAuthHelper(PyramidAuthApiServer):
        def parse_userid(self, request):
            return str(request.headers.get(self.header_remoteid, ''))

        def add_client(self, client_id, secret):
            self.remotes.update({client_id: secret})


    class RestAuthnPolicy(object):
        """ """

        def __init__(self, *args, **kwa):
            self.helper = RestAuthHelper(*args, **kwa)
            self.authenticated = set()

        def remember(self, request, principal, **kw):
            #print(**kw)
            self.helper.add_client(principal, kw['secret'])
            self.authenticated.add(principal)

        def forget(self, request):
            print ("FORGET ME!")

        def unauthenticated_userid(self, request):
            return self.helper.parse_userid(request)

        def authenticated_userid(self, request):
            userid = self.unauthenticated_userid(request)
            if userid in self.authenticated:
                return userid

        def effective_principals(self, request):
            principals = [Everyone]
            request.set_property(lambda t: self.helper, 'auth_api')
            remote_id = self.helper.parse_userid(request)

            try:
                self.helper.receive(request, tight=False)
            except AuthException as e:
                return principals
            else:
                request.add_response_callback(self.helper.send)

                try:
                    self.helper.receive(request, tight=True)
                except AuthException as e:
                    return principals + [Guest]
                else:
                    if remote_id == 'guest':
                        return principals + [TightGuest]
                    else:
                        return principals + [Authenticated, 
                                        'u:%s' % remote_id]