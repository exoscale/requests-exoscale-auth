from datetime import datetime, timezone

from exoscale_auth import ExoscaleV2Auth

import requests

_API_KEY = 'EXOxxxxxxxxxxxxxxxxxxxxxxxx'
_API_SECRET = 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'


class TestExoscaleV2Auth:
    expiration_ts = int(datetime(2077, 1, 1, tzinfo=timezone.utc).timestamp())

    def test_init(self):
        auth = ExoscaleV2Auth(key=_API_KEY, secret=_API_SECRET)
        assert auth.key == _API_KEY
        assert auth.secret == _API_SECRET.encode('utf-8')

    def test_sign_request_no_params(self):
        auth = ExoscaleV2Auth(key=_API_KEY, secret=_API_SECRET)
        req = requests.Request(
            'GET',
            'https://api.exoscale.com/v2/zone',
        ).prepare()
        auth._sign_request(req, self.expiration_ts)
        assert 'Authorization' in req.headers
        assert req.headers['Authorization'] == (
            'EXO2-HMAC-SHA256 credential=' + _API_KEY
            + ',expires=' + str(self.expiration_ts)
            + ',signature=Ntbq/p0HVmA3Zg1HHY+Lq1vjFGi7HeMrrgXDS5jRNlY='
        )

    def test_sign_request_with_params(self):
        auth = ExoscaleV2Auth(key=_API_KEY, secret=_API_SECRET)
        req = requests.Request(
            'GET',
            'https://api.exoscale.com/v2/zone',
            params={'k1': 'v1', 'k2': 'v2'},
        ).prepare()
        auth._sign_request(req, self.expiration_ts)
        assert 'Authorization' in req.headers
        assert req.headers['Authorization'] == (
            'EXO2-HMAC-SHA256 credential=' + _API_KEY
            + ',signed-query-args=k1;k2'
            + ',expires=' + str(self.expiration_ts)
            + ',signature=iqOBz13+44L5j0uJclE8hmUhQQcvtCSoPEOXYK6liqY='
        )

    def test_sign_post(self):
        auth = ExoscaleV2Auth(key=_API_KEY, secret=_API_SECRET)
        req = requests.Request(
            'POST',
            'https://api.exoscale.com/v2/load-balancer',
            json={'name': 'foo'},
        ).prepare()
        auth._sign_request(req, self.expiration_ts)
        assert 'Authorization' in req.headers
        assert req.headers['Authorization'] == (
            'EXO2-HMAC-SHA256 credential=' + _API_KEY
            + ',expires=' + str(self.expiration_ts)
            + ',signature=duldkM0+pgWRtUznj0rMrZauzsYOtSVLn1LCGcs7CcE='
        )

    def test_sign_request_with_str_msg_parts(self):
        auth = ExoscaleV2Auth(key=_API_KEY, secret=_API_SECRET)
        req = requests.Request(
            'GET',
            'https://api.exoscale.com/v2/zone',
            params={'k1': 'v1', 'k2': 'v2'},
        ).prepare()
        # explicitly set a string value to request body
        req.body = "string body"
        auth._sign_request(req, self.expiration_ts)
        assert 'Authorization' in req.headers
