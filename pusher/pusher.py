
from pusher.config import Config
from pusher.client import Client

class Pusher(object):

	def __init__(self, **kwargs):
		self.config = Config.ensure(**kwargs)
		self.client = Client(self.config)

	@classmethod
    def from_url(cls, url):
        """Alternate constructor that extracts the information from a URL.

        :param url: String containing a URL

        Usage::

          >> from pusher import Pusher
          >> p = Pusher.from_url("http://mykey:mysecret@api.pusher.com/apps/432")
        """
        return cls(Config.from_url(url))

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
        return cls(Config.from_env(env))

	def authenticate_subscription(self, channel, socket_id, custom_data=None):
        """Used to generate delegated client subscription token.

        :param channel: name of the channel to authorize subscription to
        :param socket_id: id of the socket that requires authorization
        :param custom_data: used on presence channels to provide user info
        """
        if not isinstance(channel, six.text_type):
            raise TypeError('Channel should be %s' % text)

        if not channel_name_re.match(channel):
            raise ValueError('Channel should be a valid channel, got: %s' % channel)

        if not isinstance(socket_id, six.text_type):
            raise TypeError('Socket ID should %s' % text)

        if custom_data:
            custom_data = json.dumps(custom_data)

        string_to_sign = "%s:%s" % (socket_id, channel)

        if custom_data:
            string_to_sign += ":%s" % custom_data

        signature = hmac.new(self.config.secret.encode('utf8'), string_to_sign.encode('utf8'), hashlib.sha256).hexdigest()

        auth = "%s:%s" % (self.config.key, signature)
        result = {'auth': auth}

        if custom_data:
            result['channel_data'] = custom_data

        return result

    def validate_webhook(self, key, signature, body):
        """Used to validate incoming webhook messages. When used it guarantees
        that the sender is Pusher and not someone else impersonating it.

        :param key: key used to sign the body
        :param signature: signature that was given with the body
        :param body: content that needs to be verified
        """
        if not isinstance(key, six.text_type):
            raise TypeError('key should be %s' % text)

        if not isinstance(signature, six.text_type):
            raise TypeError('signature should be %s' % text)

        if not isinstance(body, six.text_type):
            raise TypeError('body should be %s' % text)

        if key != self.config.key:
            return None

        generated_signature = six.text_type(hmac.new(self.config.secret.encode('utf8'), body.encode('utf8'), hashlib.sha256).hexdigest())

        if not compare_digest(generated_signature, signature):
            return None

        try:
            body_data = json.loads(body)
        except ValueError:
            return None

        time_ms = body_data.get('time_ms')
        if not time_ms:
            return None

        print(abs(time.time()*1000 - time_ms))
        if abs(time.time()*1000 - time_ms) > 300000:
            return None

        return body_data

    def trigger(self, *args, **kwargs):
    	return self.client.trigger(*args, **kwargs)

    def channels_info(self, *args, **kwargs):
    	return self.client.channels_info(*args, **kwargs)

   	def channel_info(self, *args, **kwargs):
   		return self.client.channel_info(*args, **kwargs)

   	def users_info(self, *args, **kwargs):
   		return self.client.users_info(*args, **kwargs)
