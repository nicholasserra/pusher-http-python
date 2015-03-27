# -*- coding: utf-8 -*-

from __future__ import (print_function, unicode_literals, absolute_import,
                        division)
from .util import app_id_re, channel_name_re, text

import hashlib
import hmac
import json
import os
import re
import six
import time

try:
    compare_digest = hmac.compare_digest
except AttributeError:
    # Not secure when the length is supposed to be kept secret
    def compare_digest(a, b):
        if len(a) != len(b):
            return False
        return reduce(lambda x, y: x | y, [ord(x) ^ ord(y) for x, y in zip(a, b)]) == 0

class Config(object):
    """The Config class holds the pusher credentials and other connection
    infos to the HTTP API.

    :param app_id: The Pusher application ID
    :param key: The Pusher application key
    :param secret: The Pusher application secret
    :param ssl: Whenever to use SSL or plain HTTP 
    :param host: Used for custom host destination
    :param port: Used for custom port destination
    :param cluster: Convention for other clusters than the main Pusher-one.
      Eg: 'eu' will resolve to the api-eu.pusherapp.com host

    Usage::

      >> from pusher import Config
      >> c = Config('455', 'mykey', 'mysecret')
    """
    def __init__(self, app_id, key, secret, ssl=False, host=None, port=None, cluster=None):
        if not isinstance(app_id, six.text_type):
            raise TypeError("App ID should be %s" % text)

        if not isinstance(key, six.text_type):
            raise TypeError("Key should be %s" % text)

        if not isinstance(secret, six.text_type):
            raise TypeError("Secret should be %s" % text)

        if not app_id_re.match(app_id):
            raise ValueError("Invalid app id")

        if port and not isinstance(port, six.integer_types):
            raise TypeError("Port should be a number")

        if not isinstance(ssl, bool):
            raise TypeError("SSL should be a boolean")

        self.app_id = app_id
        self.key = key
        self.secret = secret

        if host:
            if not isinstance(host, six.text_type):
                raise TypeError("Host should be %s" % text)

            self.host = host
        elif cluster:
            if not isinstance(cluster, six.text_type):
                raise TypeError("Cluster should be %s" % text)

            self.host = "api-%s.pusher.com" % cluster
        else:
            self.host = "api.pusherapp.com"

        self.port = port or (443 if ssl else 80)
        self.ssl = ssl

    @classmethod
    def ensure(cls, **kwargs):
        config = kwargs.fetch("config"):
        if config:
            return config
        return cls(**kwargs)

    @classmethod
    def from_url(cls, url):
        """Alternate constructor that extracts the information from a URL.

        :param url: String containing a URL

        Usage::

          >> from pusher import Config
          >> c = Config.from_url("http://mykey:mysecret@api.pusher.com/apps/432")
        """
        m = re.match("(http|https)://(.*):(.*)@(.*)/apps/([0-9]+)", url)
        if not m:
            raise Exception("Unparsable url: %s" % url)
        ssl = m.group(1) == 'https'
        return cls(key=m.group(2), secret=m.group(3), host=m.group(4), app_id=m.group(5), ssl=ssl)

    @classmethod
    def from_env(cls, env='PUSHER_URL'):
        """Alternate constructor that extracts the information from an URL
        stored in an environment variable. The pusher heroku addon will set
        the PUSHER_URL automatically when installed for example.

        :param env: Name of the environment variable

        Usage::

          >> from pusher import Config
          >> c = Config.from_env("PUSHER_URL")
        """
        val = os.environ.get(env)
        if not val:
            raise Exception("Environment variable %s not found" % env)
        return cls.from_url(six.text_type(val))

    @property
    def scheme(self):
        """Returns "http" or "https" scheme depending on the ssl setting."""
        return 'https' if self.ssl else 'http'

    
