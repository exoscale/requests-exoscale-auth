from __future__ import unicode_literals

import hashlib
import hmac

from datetime import datetime

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
