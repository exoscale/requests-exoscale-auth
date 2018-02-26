Requests-exoscale-auth
======================

Exoscale APIs support for Python-Requests.

Installation::

    pip install requests-exoscale-auth

Usage:

.. code-block:: python

    import requests
    from exoscale_auth import ExoscaleAuth

    auth = ExoscaleAuth('my-key', 'my-secret')
    response = requests.get('https://portal.exoscale.com/api/account',
                            auth=auth)
