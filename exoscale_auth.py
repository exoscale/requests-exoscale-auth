from __future__ import unicode_literals

import hashlib
import hmac
import time

from base64 import standard_b64encode
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
        expiration_ts = int(time.time() + 10 * 60)
        self._sign_request(request, expiration_ts)
        return request

    def _sign_request(self, request, expiration_ts):
        auth_header = 'EXO2-HMAC-SHA256 credential={}'.format(self.key)
        msg_parts = []

        # Request method/URL path
        msg_parts.append('{method} {path}'.format(
            method=request.method, path=urlparse(request.url).path
        ))

        # Request body
        msg_parts.append(body.encode('utf-8') if request.body else u'')

        # Request query string parameters
        # Important: this is order-sensitive, we have to have to sort
        # parameters alphabetically to ensure signed # values match the
        # names listed in the 'signed-query-args=' signature pragma.
        params = parse_qs(urlparse(request.url).query)
        signed_params = sorted(params)
        params_values = []
        for p in signed_params:
            if len(params[p]) != 1:
                continue
            params_values.append(params[p][0])
        msg_parts.append(''.join(params_values))
        if signed_params:
            auth_header += ',signed-query-args={}'.format(';'.join(signed_params))

        # Request headers -- none at the moment
        # Note: the same order-sensitive caution for query string parameters
        # applies to headers.
        msg_parts.append('')

        # Request expiration date (UNIX timestamp)
        msg_parts.append(str(expiration_ts))
        auth_header += ',expires=' + str(expiration_ts)

        msg = '\n'.join(msg_parts)
        signature = hmac.new(
            self.secret, msg=msg.encode('utf-8'), digestmod=hashlib.sha256
        ).digest()

        auth_header += ',signature=' + str(
            standard_b64encode(bytes(signature)), 'utf-8'
        )

        request.headers['Authorization'] = auth_header
