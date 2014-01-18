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

    def sign(self, secret, timestamp, *args):
        """Tighter HMAC-SHA256 that uses the UTC timestamp and multiple
        passes.
        """
        #print(timestamp)
        #print(args[0])
        #print(args[1])
        
        h = hmac.new(secret.encode(), None, hashlib.sha256)
        for i in range(self.passes):
            h.update(timestamp.encode())
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
        # Prepare some data for signing.
        remote_id = str(request.headers.get(self.header_remoteid, ''))
        payload = json_loads(response.body.decode('utf-8'))        

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
    import pyramid.httpexceptions as exc
    from pyramid.view import view_config

    # Just a commonly used kwarg handler.
    def _common_kwa(kwa):
        if 'registry_key' in kwa:
            registry_key = kwa['registry_key']
            del kwa['registry_key']
        else:
            registry_key = 'auth_api'

        if 'tight_auth' in kwa:
            tight_auth = kwa['tight_auth']
            del kwa['tight_auth']
        else:
            tight_auth = True
        return registry_key, tight_auth

    # Commonly code useds by authenticated views.
    def _auth_view(request, auth_api, tight=True,
                    model_type=collections.OrderedDict):

        try:
            auth_api.receive(request, tight=tight, default_type=model_type)
        except AuthException as e:
            # Log and throw HTTP exception.
            log.warn("AuthException: %s" % e)
            raise exc.HTTPForbidden()            

        # Set up response callback for sending.
        request.add_response_callback(auth_api.send)

        return request


    def auth_view_config(model_type, *args, **kwa):
        """Pyramid view decorator to require authentication on the
        view_config callable.
        """
        registry_key, tight_auth = _common_kwa(kwa)

        def decorator(view_callable):
            def _inner(request):
                # Get the Auth API from the registry..
                auth_api = request.registry.settings[registry_key]

                request = _auth_view(request, auth_api, tight=tight_auth,
                                        model_type=model_type)

                return view_callable(request)
                
            _inner.__name__ = view_callable.__name__
            kwa['_depth'] = 1 # instruct venusian to do something. (??)
            return view_config(*args, **kwa)(_inner)
        return decorator


    def ping_view(**kwa):
        """Pyramid view callable to return basic information used to
        tighten the security of the auth.
        """
        registry_key, _ = _common_kwa(kwa)

        def ping(request):
            auth_api = request.registry.settings[registry_key]

            request = _auth_view(request, auth_api, tight=False)
            return {'_addr': request.client_addr,
                    '_time': int(auth_api.time_provider())}

        return ping