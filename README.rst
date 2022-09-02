Requests-exoscale-auth
======================

Exoscale APIs support for Python-Requests.

Installation::

    pip install requests-exoscale-auth

Usage:

.. code-block:: python

    import requests
    from exoscale_auth import ExoscaleV2Auth

    auth = ExoscaleV2Auth("my-key", "my-secret")
    response = requests.get("https://api-ch-gva-2.exoscale.com/v2/instance",
                            auth=auth)
