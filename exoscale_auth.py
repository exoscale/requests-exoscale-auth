from __future__ import unicode_literals

import hashlib
import hmac

from base64 import standard_b64encode
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse, parse_qs

from requests.auth import AuthBase


class ExoscaleAuth(AuthBase):
    def __init__(self, key, secret):
        self.key = key
        self.secret = secret.encode('utf-8')

    def __call__(self, request):
        body = request.body or b''
        if hasattr(body, 'encode'):
            body = body.encode('utf-8')
        date = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
        string_to_sign = '{0}{1}'.format(request.url,
                                         date).encode('utf-8') + body
        signature = hmac.new(self.secret,
                             msg=string_to_sign,
                             digestmod=hashlib.sha256).hexdigest()
        auth = u'Exoscale-HMAC-SHA256 {0}:{1}'.format(self.key, signature)
        request.headers.update({
            'Exoscale-Date': date,
            'Authorization': auth,
        })
        return request


class ExoscaleV2Auth(AuthBase):
    def __init__(self, key, secret):
        self.key = key
        self.secret = secret.encode('utf-8')

    def __call__(self, request):
        expiration = datetime.now(tz=timezone.utc) + timedelta(minutes=10)
        self._sign_request(request, expiration)
        return request

    def _sign_request(self, request, expiration):
        auth_header = 'EXO2-HMAC-SHA256 credential={}'.format(self.key)

        # Request method/URL path
        msg = '{method} {path}\n'.format(
            method=request.method, path=urlparse(request.url).path
        )

        # Request body
        if request.body:
            msg += body.encode('utf-8')
        msg += '\n'

        # Request query string parameters
        # Important: this is order-sensitive, we have to have to sort
        # parameters alphabetically to ensure signed # values match the
        # names listed in the 'signed-query-args=' signature pragma.
        params = parse_qs(urlparse(request.url).query)
        signed_params = sorted(params.keys())
        for p in signed_params:
            if len(params[p]) != 1:
                continue
            msg += params[p][0]
        msg += '\n'
        if len(signed_params) > 0:
            auth_header += ',signed-query-args={}'.format(';'.join(signed_params))

        # Request headers -- none at the moment
        # Note: the same order-sensitive caution for query string parameters
        # applies to headers.
        msg += '\n'

        # Request expiration date (UNIX timestamp, no line return)
        ts = str(int(expiration.timestamp()))
        msg += ts
        auth_header += ',expires=' + ts

        signature = hmac.new(
            self.secret, msg=msg.encode('utf-8'), digestmod=hashlib.sha256
        ).digest()

        auth_header += ',signature=' + str(
            standard_b64encode(bytes(signature)), 'utf-8'
        )

        request.headers.update({'Authorization': auth_header})

