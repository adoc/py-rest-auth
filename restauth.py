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

    def unsign(self, secret, timestamp, signature, *args):
        """
        """
        timestamp = int(timestamp)
        utcnow = int(self.time_provider())
        delta = utcnow - timestamp;
        if abs(delta) > self.threshold*1000:
            raise SignatureTimeout("Signature it too old. %s:%s" %
                                    (utcnow, timestamp))
        challenge = self.sign(secret, str(timestamp), *args)
        if signature != challenge:
            raise SignatureBad("Incorrect HMAC challenge. %s:%s" %
                                (signature, challenge))

    def send(self, remote_id, payload):
        """
        """
        secret = self.remotes[remote_id]
        now = int(self.time_provider())

        payload = json_dumps(payload)
        meta = json_dumps({'_cid': self.sender_id})
        now = json_dumps(now)

        return (self.sign(secret, now, payload, meta), now)

    def receive(self, remote_id, timestamp, signature, payload):
        """
        """
        if not remote_id in self.remotes:
            raise ClientBad("Remote id %s is not a valid client." % remote_id)

        payload = json_dumps(payload)
        meta = json_dumps({'_cid': remote_id})
        secret = self.remotes[remote_id]

        self.unsign(secret, timestamp, signature, payload, meta)


class PyramidAuthApiServer(AuthApi):
    """
    """
    def __init__(self, sender_id, remotes={}, passes=100, threshold=600,
                    time_provider=time.time, header_signature='',
                    header_timestamp='', header_remoteid=''):
        """
        """
        AuthApi.__init__(self, sender_id, remotes, passes, threshold, time.time)
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

    def receive(self, request, default_type=collections.OrderedDict):
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

        # Invoke the Api.
        AuthApi.receive(self, remote_id, timestamp, signature, payload)


# Pyramid View Config
# ===================
try:
    import pyramid
except ImportError:
    # Log something here.
    log.info("Pyramid is unavailable. You won't be able to use "
                "`auth_view_config`")
else:
    import pyramid.httpexceptions as exc
    from pyramid.view import view_config

    def auth_view_config(model_type, *args, **kwa):
        """
        """
        if 'registry_key' in kwa:
            registry_key = kwa['registry_key']
            del kwa['registry_key']
        else:
            registry_key = 'auth_api'

        def decorator(view_callable):
            def _inner(request):
                # Get the Auth API.
                auth_api = request.registry.settings[registry_key]

                # Handle receipt
                auth_api.receive(request, default_type=model_type)

                # Set up response callback for sending.
                request.add_response_callback(auth_api.send)

                return view_callable(request)
                
            _inner.__name__ = view_callable.__name__
            kwa['_depth'] = 1 # instruct venusian to do something. (??)
            return view_config(*args, **kwa)(_inner)
        return decorator