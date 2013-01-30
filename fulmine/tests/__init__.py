from functools import wraps
import json
from urlparse import parse_qs, urlparse

from django.conf import settings, UserSettingsHolder
from django.contrib.auth.models import User
from django.test import Client, RequestFactory, TestCase
from django.utils.unittest import expectedFailure

from fulmine.forms import make_token_form
from fulmine.middleware import BearerAuthMiddleware
from fulmine.models import AuthorizationGrant
from fulmine.timeutils import mock_time

try:
    from django.test.utils import override_settings
except ImportError:
    # This version of override_settings is for compatibility with Django <1.4
    # Note it lacks support for settings_changed signal.
    class override_settings(object):
        """
        Acts as either a decorator, or a context manager. If it's a decorator it
        takes a function and returns a wrapped function. If it's a contextmanager
        it's used with the ``with`` statement. In either event entering/exiting
        are called before and after, respectively, the function/block is executed.
        """
        def __init__(self, **kwargs):
            self.options = kwargs
            self.wrapped = settings._wrapped

        def __enter__(self):
            self.enable()

        def __exit__(self, exc_type, exc_value, traceback):
            self.disable()

        def __call__(self, test_func):
            from django.test import TransactionTestCase
            if isinstance(test_func, type) and issubclass(test_func, TransactionTestCase):
                original_pre_setup = test_func._pre_setup
                original_post_teardown = test_func._post_teardown
                def _pre_setup(innerself):
                    self.enable()
                    original_pre_setup(innerself)
                def _post_teardown(innerself):
                    original_post_teardown(innerself)
                    self.disable()
                test_func._pre_setup = _pre_setup
                test_func._post_teardown = _post_teardown
                return test_func
            else:
                @wraps(test_func)
                def inner(*args, **kwargs):
                    with self:
                        return test_func(*args, **kwargs)
            return inner

        def enable(self):
            override = UserSettingsHolder(settings._wrapped)
            for key, new_value in self.options.items():
                setattr(override, key, new_value)
            settings._wrapped = override

        def disable(self):
            settings._wrapped = self.wrapped
            for key in self.options:
                new_value = getattr(settings, key, None)


def resource_server_settings():
    return override_settings(
            MIDDLEWARE_CLASSES = (
                'django.middleware.common.CommonMiddleware',
                'fulmine.tests.BearerAuthTestMiddleware',
                'django.middleware.csrf.CsrfViewMiddleware',
                'django.contrib.auth.middleware.AuthenticationMiddleware',
    ))

class Rfc6749Test(TestCase):
    urls = 'fulmine.tests.urls'

    def setUp(self):
        User.objects.create_user(username='testuser',
                                 email='test@example.com',
                                 password='test')

    def test_authcode_authorization(self):
        self.client.login(username='testuser', password='test')
        # 1) RO UA opens authorization endpoint
        endpoint_path = '/authorize/'
        args = dict(
            response_type='code',
            client_id='1234',
            redirect_uri='http://example.com/destination?par1=val1',
            scope='read_all write_all',
            state='abcdef1234567890'
        )
        response = self.client.get(
            endpoint_path,
            data=args,
            HTTP_REFERER='http://example.com/source/',
        )

        # 2) RO grants authorization
        response = self.client.post(
            endpoint_path,
            data=args,
            HTTP_REFERER=endpoint_path,
        )
        self.assertEqual(response.status_code,
                          302,
                          'grant endpoint must redirect to redirect_uri')
        o = urlparse(response['Location'])
        self.assertEqual(o.scheme, 'http')
        self.assertEqual(o.netloc, 'example.com')
        self.assertEqual(o.path, '/destination')
        self.assertEqual(o.fragment, '')
        redirect_args = parse_qs(o.query)
        self.assertEqual(redirect_args['par1'], ['val1'])
        self.assertIn('code', redirect_args)
        self.assertIn('state', redirect_args)
        self.assertEqual(redirect_args['state'], [args['state']])
        auth_code, = redirect_args['code']

        # 3) is grant persisted?
        try:
            grant = AuthorizationGrant.objects.get(client_id='1234',
                user__username='testuser')
        except AuthorizationGrant.DoesNotExist:
            self.fail('authorization code must be persisted')

    def test_authcode_invalid_client_id_dialog(self):
        self.client.login(username='testuser', password='test')
        # 1) RO UA opens authorization endpoint
        endpoint_path = '/authorize/'
        args = dict(
            response_type='code',
            client_id='invalid',
            redirect_uri='http://example.com/destination?par1=val1',
            scope='read_all write_all',
            state='abcdef1234567890'
        )
        response = self.client.get(
            endpoint_path,
            data=args,
            HTTP_REFERER='http://example.com/source/',
        )
        self.assertEqual(response.status_code, 400, 'auth dialog must be an error page')

    # This is known to fail because there is no client check
    # when authcode is issued. This could lead to a potential
    # vulnerability if newly issued client_ids can be predicted.
    @expectedFailure
    def test_authcode_invalid_client_id_grant(self):
        self.client.login(username='testuser', password='test')
        # 1) RO UA opens authorization endpoint
        endpoint_path = '/authorize/'
        args = dict(
            response_type='code',
            client_id='invalid',
            redirect_uri='http://example.com/destination?par1=val1',
            scope='read_all write_all',
            state='abcdef1234567890'
        )
        response = self.client.post(
            endpoint_path,
            data=args,
            HTTP_REFERER=endpoint_path,
        )
        self.assertEqual(response.status_code, 400,
                         'auth grant must give error 400, got status = %s'
                         % response.status_code)

    def test_authcode_authorization_csrf(self):
        self.client = Client(enforce_csrf_checks=True)
        self.client.login(username='testuser', password='test')
        # 1) RO UA opens authorization endpoint
        endpoint_path = '/authorize/'
        args = dict(
            response_type='code',
            client_id='1234',
            redirect_uri='http://example.com/destination?par1=val1',
            scope='read_all write_all',
            state='abcdef1234567890'
        )
        response = self.client.get(
            endpoint_path,
            data=args,
            HTTP_REFERER='http://example.com/source/',
        )

        self.assertIn('csrftoken', response.cookies)
        args['csrfmiddlewaretoken'] = response.cookies['csrftoken'].value

        # 2) RO grants authorization
        response = self.client.post(
            endpoint_path,
            data=args,
            HTTP_REFERER=endpoint_path,
        )
        self.assertEqual(response.status_code,
                          302,
                          'grant endpoint must redirect to redirect_uri')
        o = urlparse(response['Location'])
        self.assertEqual(o.scheme, 'http')
        self.assertEqual(o.netloc, 'example.com')
        self.assertEqual(o.path, '/destination')
        self.assertEqual(o.fragment, '')
        redirect_args = parse_qs(o.query)
        self.assertEqual(redirect_args['par1'], ['val1'])
        self.assertIn('code', redirect_args)
        self.assertIn('state', redirect_args)
        self.assertEqual(redirect_args['state'], [args['state']])
        auth_code, = redirect_args['code']

    def test_implicit_authorization(self):
        self.client.login(username='testuser', password='test')
        # 1) RO UA opens authorization endpoint
        endpoint_path = '/authorize/'
        args = dict(
            response_type='token',
            client_id='1234',
            redirect_uri='http://example.com/destination?par1=val1',
            scope='read_all write_all',
            state='abcdef1234567890'
        )
        response = self.client.get(
            endpoint_path,
            data=args,
            HTTP_REFERER='http://example.com/source/',
        )

        # 2) RO grants authorization
        response = self.client.post(
            endpoint_path,
            data=args,
            HTTP_REFERER=endpoint_path,
        )
        self.assertEqual(response.status_code,
                         302,
                         'grant endpoint must redirect to redirect_uri')
        o = urlparse(response['Location'])
        self.assertEqual(o.scheme, 'http')
        self.assertEqual(o.netloc, 'example.com')
        self.assertEqual(o.path, '/destination')
        self.assertEqual(o.query, 'par1=val1')
        redirect_args = parse_qs(o.fragment)
        self.assertIn('access_token', redirect_args)
        self.assertIn('state', redirect_args)
        self.assertNotIn('refresh_token', redirect_args)
        self.assertEqual(redirect_args['token_type'], ['bearer'])
        self.assertEqual(redirect_args['state'], [args['state']])
        token, = redirect_args['access_token']
        self.assertNotEqual(len(token), 0)

    def test_implicit_authorization_csrf(self):
        self.client = Client(enforce_csrf_checks=True)
        self.client.login(username='testuser', password='test')
        # 1) RO UA opens authorization endpoint
        endpoint_path = '/authorize/'
        args = dict(
            response_type='token',
            client_id='1234',
            redirect_uri='http://example.com/destination?par1=val1',
            scope='read_all write_all',
            state='abcdef1234567890'
        )
        response = self.client.get(
            endpoint_path,
            data=args,
            HTTP_REFERER='http://example.com/source/',
        )
        self.assertIn('csrftoken', response.cookies)
        args['csrfmiddlewaretoken'] = response.cookies['csrftoken'].value

        # 2) RO grants authorization
        response = self.client.post(
            endpoint_path,
            data=args,
            HTTP_REFERER=endpoint_path,
        )
        self.assertEqual(response.status_code,
                         302,
                         'grant endpoint must redirect to redirect_uri')
        o = urlparse(response['Location'])
        self.assertEqual(o.scheme, 'http')
        self.assertEqual(o.netloc, 'example.com')
        self.assertEqual(o.path, '/destination')
        self.assertEqual(o.query, 'par1=val1')
        redirect_args = parse_qs(o.fragment)
        self.assertIn('access_token', redirect_args)
        self.assertIn('token_type', redirect_args)
        self.assertIn('state', redirect_args)
        self.assertNotIn('refresh_token', redirect_args)
        self.assertEqual(redirect_args['state'], [args['state']])
        token, = redirect_args['access_token']
        self.assertNotEqual(len(token), 0)

    def test_authorization_csrf_invalid(self):
        self.client = Client(enforce_csrf_checks=True)
        self.client.login(username='testuser', password='test')
        # 1) RO UA opens authorization endpoint
        endpoint_path = '/authorize/'
        args = dict(
            response_type='code',
            client_id='1234',
            redirect_uri='http://example.com/destination?par1=val1',
            scope='read_all write_all',
            state='abcdef1234567890'
        )
        response = self.client.get(
            endpoint_path,
            data=args,
            HTTP_REFERER='http://example.com/source/',
        )
        csrftoken = response.cookies['csrftoken'].value

        # there is no args['csrfmiddlewaretoken'] at this point

        # 2) RO grants authorization
        response = self.client.post(
            endpoint_path,
            data=args,
            HTTP_REFERER=endpoint_path,
        )
        self.assertEqual(response.status_code,
                         403,
                         'grant endpoint must not accept a request without a csrf token')

        # generate a token different from the valid one
        from base64 import urlsafe_b64decode, urlsafe_b64encode
        decoded = urlsafe_b64decode(csrftoken)
        new_decoded = decoded[:-1] + chr((ord(decoded[-1]) + 1) % 256)
        new_token = urlsafe_b64encode(new_decoded)
        args['csrfmiddlewaretoken'] = new_token

        response = self.client.post(
            endpoint_path,
            data=args,
            HTTP_REFERER=endpoint_path,
        )
        self.assertEqual(response.status_code,
                         403,
                         'grant endpoint must not accept a request with an invalid csrf token')

    def test_authcode_token(self):
        self.client.login(username='testuser', password='test')
        # 1) get auth_code from resource owner user-agent
        redirect_uri = 'http://example.com/destination?par1=val1'
        args = dict(
            response_type='code',
            client_id='public',
            redirect_uri=redirect_uri,
            scope='read_all write_all',
            state='abcdef1234567890'
        )
        self.client.get('/authorize/', data=args,
                        HTTP_REFERER='http://example.com/source/')
        response = self.client.post(
            '/authorize/',
            data=args,
        )
        o = urlparse(response['Location'])
        redirect_args = parse_qs(o.query)
        auth_code, = redirect_args['code']

        # 2) exchange it for a token
        self.client = Client()
        args = dict(
            grant_type='authorization_code',
            client_id='public',
            code=auth_code,
            redirect_uri=redirect_uri,
        )
        response = self.client.post(
            '/token/',
            data=args,
            follow=True,
        )
        self.assertTrue(200 <= response.status_code < 300,
                        'token endpoint must respond with a success code')
        self.assertEqual(response['Cache-Control'], 'no-store')
        self.assertEqual(response['Pragma'], 'no-cache')
        self.assertEqual(response['Content-type'], 'application/json')
        content = json.loads(response.content)
        self.assertIn('access_token', content)
        self.assertIn('token_type', content)
        self.assertEqual(content['token_type'], 'bearer')
        access_token = content['access_token']

        # 3) test the token is valid
        with resource_server_settings():
            client = Client(enforce_csrf_checks=True)
            response = client.get('/resource/',
                HTTP_AUTHORIZATION='Bearer %s' % access_token)
            # test view returns client_id:username if authentication
            # is ok, "FAIL" otherwise
            self.assertEqual(response.content, 'public:testuser')

    def test_implicit_token(self):
        self.client.login(username='testuser', password='test')
        # 1) RO UA opens authorization endpoint
        endpoint_path = '/authorize/'
        args = dict(
            response_type='token',
            client_id='public',
            redirect_uri='http://example.com/destination?par1=val1',
            scope='read_all write_all',
            state='abcdef1234567890'
        )
        response = self.client.get(
            endpoint_path,
            data=args,
            HTTP_REFERER='http://example.com/source/',
        )

        # 2) RO grants authorization
        response = self.client.post(
            endpoint_path,
            data=args,
            HTTP_REFERER=endpoint_path,
        )
        o = urlparse(response['Location'])
        redirect_args = parse_qs(o.fragment)
        access_token, = redirect_args['access_token']

        # 3) test the token is valid
        with resource_server_settings():
            client = Client(enforce_csrf_checks=True)
            response = client.get('/resource/',
                HTTP_AUTHORIZATION='Bearer %s' % access_token)
            # test view returns client_id:username if authentication
            # is ok, "FAIL" otherwise
            self.assertEqual(response.content, 'public:testuser')

    @resource_server_settings()
    def test_non_authorized_access(self):
        client = Client(enforce_csrf_checks=True)
        # no Authorization header is given
        response = client.get('/resource/')
        # test view returns client_id:username if authentication
        # is ok, "FAIL" otherwise
        self.assertEqual(response.content, 'FAIL')

    @mock_time
    def test_access_token_expiry(self, t):
        import django.contrib.sessions.backends.base as sessionsbase
        import django.contrib.sessions.backends.db as sessionsdb
        t.patch_modules([sessionsbase, sessionsdb])

        self.client.login(username='testuser', password='test')
        # 1) obtain access and refresh token
        redirect_uri = 'http://example.com/destination?par1=val1'
        args = dict(
            response_type='code',
            client_id='public',
            redirect_uri=redirect_uri,
            scope='read_all write_all',
            state='abcdef1234567890'
        )
        self.client.get('/authorize/', data=args,
                        HTTP_REFERER='http://example.com/source/')
        response = self.client.post(
            '/authorize/',
            data=args,
        )
        o = urlparse(response['Location'])
        redirect_args = parse_qs(o.query)
        auth_code, = redirect_args['code']

        self.client = Client()
        args = dict(
            grant_type='authorization_code',
            client_id='public',
            code=auth_code,
            redirect_uri=redirect_uri,
        )
        response = self.client.post(
            '/token/',
            data=args,
            follow=True,
        )
        content = json.loads(response.content)
        access_token = content['access_token']
        expires_in = content['expires_in']

        # 2) let access token expire
        t.add_time(seconds=expires_in)

        # 3) call to protected resource must fail
        with resource_server_settings():
            client = Client(enforce_csrf_checks=True)
            response = client.get('/resource/',
                HTTP_AUTHORIZATION='Bearer %s' % access_token)
            self.assertEqual(response.content, 'FAIL')

    @mock_time
    def test_refresh_token(self, t):
        import django.contrib.sessions.backends.base as sessionsbase
        import django.contrib.sessions.backends.db as sessionsdb
        t.patch_modules([sessionsbase, sessionsdb])

        self.client.login(username='testuser', password='test')
        # 1) obtain access and refresh token
        redirect_uri = 'http://example.com/destination?par1=val1'
        args = dict(
            response_type='code',
            client_id='public',
            redirect_uri=redirect_uri,
            scope='read_all write_all',
            state='abcdef1234567890'
        )
        self.client.get('/authorize/', data=args,
                        HTTP_REFERER='http://example.com/source/')
        response = self.client.post(
            '/authorize/',
            data=args,
        )
        o = urlparse(response['Location'])
        redirect_args = parse_qs(o.query)
        auth_code, = redirect_args['code']

        self.client = Client()
        args = dict(
            grant_type='authorization_code',
            client_id='public',
            code=auth_code,
            redirect_uri=redirect_uri,
        )
        response = self.client.post(
            '/token/',
            data=args,
            follow=True,
        )
        content = json.loads(response.content)
        refresh_token = content['refresh_token']
        expires_in = content['expires_in']

        # 2) let access token expire
        t.add_time(seconds=expires_in)

        # 3) obtain refreshed access token
        self.client = Client()
        args = dict(
            grant_type='refresh_token',
            refresh_token=refresh_token,
        )
        response = self.client.post(
            '/token/',
            data=args,
            follow=True,
        )
        self.assertTrue(200 <= response.status_code < 300,
                        'token endpoint must respond with a success code')
        self.assertEqual(response['Cache-Control'], 'no-store')
        self.assertEqual(response['Pragma'], 'no-cache')
        self.assertEqual(response['Content-type'], 'application/json')
        content = json.loads(response.content)
        self.assertIn('access_token', content)
        self.assertIn('token_type', content)
        self.assertEqual(content['token_type'], 'bearer')
        access_token = content['access_token']

        # 4) call to protected resource must succeed
        with resource_server_settings():
            client = Client(enforce_csrf_checks=True)
            response = client.get('/resource/',
                HTTP_AUTHORIZATION='Bearer %s' % access_token)
            # test view returns client_id:username if authentication
            # is ok, "FAIL" otherwise
            self.assertEqual(response.content, 'public:testuser')

    def test_update_scope(self):
        self.client.login(username='testuser', password='test')
        # 1) grant a scope
        redirect_uri = 'http://example.com/destination?par1=val1'
        args = dict(
            response_type='code',
            client_id='public',
            redirect_uri=redirect_uri,
            scope='scope1',
            state='abcdef1234567890'
        )
        self.client.get('/authorize/', data=args,
                        HTTP_REFERER='http://example.com/source/')
        response = self.client.post(
            '/authorize/',
            data=args,
        )

        # 2) grant a broader scope and get the authorization code
        args['scope'] = 'scope1 scope2'
        self.client.get('/authorize/', data=args,
                        HTTP_REFERER='http://example.com/source/')
        response = self.client.post(
            '/authorize/',
            data=args,
        )
        o = urlparse(response['Location'])
        redirect_args = parse_qs(o.query)
        auth_code, = redirect_args['code']

        # 2) exchange it for a token
        self.client = Client()
        args = dict(
            grant_type='authorization_code',
            client_id='public',
            code=auth_code,
            redirect_uri=redirect_uri,
        )
        response = self.client.post(
            '/token/',
            data=args,
            follow=True,
        )
        self.assertTrue(200 <= response.status_code < 300,
                        'token endpoint must respond with a success code')
        self.assertEqual(response['Cache-Control'], 'no-store')
        self.assertEqual(response['Pragma'], 'no-cache')
        self.assertEqual(response['Content-type'], 'application/json')
        content = json.loads(response.content)
        self.assertIn('access_token', content)
        self.assertIn('token_type', content)
        self.assertEqual(content['token_type'], 'bearer')
        access_token = content['access_token']

        # 3) test the token is valid and has the right scope
        with resource_server_settings():
            client = Client(enforce_csrf_checks=True)
            response = client.get('/resource/',
                HTTP_AUTHORIZATION='Bearer %s' % access_token)
            # test view returns client_id:username if authentication
            # is ok, "FAIL" otherwise
            self.assertEqual(response.content, 'public:testuser')

            response = client.get('/scope/',
                HTTP_AUTHORIZATION='Bearer %s' % access_token)
            # test view returns the scope
            self.assertEqual(response.content, 'scope1 scope2')

    def test_password_token(self):
        # 2) get an access token via password grant_type
        self.client = Client()
        args = dict(
            grant_type='password',
            username='testuser',
            password='test',
            scope='read_all write_all',
        )
        response = self.client.post(
            '/token/',
            data=args,
            follow=True,
            HTTP_X_TEST_CLIENT_AUTH='confidential',
        )
        self.assertTrue(200 <= response.status_code < 300,
                        'token endpoint must respond with a success code')
        self.assertEqual(response['Cache-Control'], 'no-store')
        self.assertEqual(response['Pragma'], 'no-cache')
        self.assertEqual(response['Content-type'], 'application/json')
        content = json.loads(response.content)
        self.assertIn('access_token', content)
        self.assertIn('token_type', content)
        self.assertEqual(content['token_type'], 'bearer')
        access_token = content['access_token']

        # 3) test the token is valid
        with resource_server_settings():
            client = Client(enforce_csrf_checks=True)
            response = client.get('/resource/',
                HTTP_AUTHORIZATION='Bearer %s' % access_token)
            # test view returns client_id:username if authentication
            # is ok, "FAIL" otherwise
            self.assertEqual(response.content, 'confidential:testuser')

    def test_token_unsupported_grant_type(self):
        self.client = Client()
        args = dict(
            grant_type='does_not_exist',
            username='testuser',
            password='test',
            scope='read_all write_all',
        )
        response = self.client.post(
            '/token/',
            data=args,
            follow=True,
            HTTP_X_TEST_CLIENT_AUTH='confidential',
        )
        self.assertEqual(400, response.status_code)
        content = json.loads(response.content)
        self.assertEqual(content['error'], 'unsupported_grant_type')

    def test_client_credentials_token(self):
        # 1) get an access token via client_credentials grant_type
        self.client = Client()
        args = dict(
            grant_type='client_credentials',
        )
        response = self.client.post(
            '/token/',
            data=args,
            follow=True,
            HTTP_X_TEST_CLIENT_AUTH='confidential',
        )
        self.assertTrue(200 <= response.status_code < 300,
                        'token endpoint must respond with a success code')
        self.assertEqual(response['Cache-Control'], 'no-store')
        self.assertEqual(response['Pragma'], 'no-cache')
        self.assertEqual(response['Content-type'], 'application/json')
        content = json.loads(response.content)
        self.assertIn('access_token', content)
        self.assertIn('token_type', content)
        self.assertEqual(content['token_type'], 'bearer')
        access_token = content['access_token']

        # 2) test the token is valid
        with resource_server_settings():
            client = Client(enforce_csrf_checks=True)
            response = client.get('/resource/',
                HTTP_AUTHORIZATION='Bearer %s' % access_token)
            # test view returns client_id:username if authentication
            # is ok, "FAIL" otherwise
            self.assertEqual(response.content, 'confidential:')

    def test_extra_grant_type_token(self):
        # 1) get an access token via an extra grant type
        self.client = Client()
        args = dict(
            grant_type='magic_number',
            magic_number='42',
        )
        response = self.client.post(
            '/token_extra/',
            data=args,
            follow=True,
        )
        self.assertTrue(200 <= response.status_code < 300,
                        'token endpoint must respond with a success code')
        self.assertEqual(response['Cache-Control'], 'no-store')
        self.assertEqual(response['Pragma'], 'no-cache')
        self.assertEqual(response['Content-type'], 'application/json')
        content = json.loads(response.content)
        self.assertIn('access_token', content)
        self.assertIn('token_type', content)
        self.assertEqual(content['token_type'], 'bearer')
        access_token = content['access_token']

        # 2) test the token is valid
        with resource_server_settings():
            client = Client(enforce_csrf_checks=True)
            response = client.get('/resource/',
                HTTP_AUTHORIZATION='Bearer %s' % access_token)
            # test view returns client_id:username if authentication
            # is ok, "FAIL" otherwise
            self.assertEqual(response.content, 'magic:')

    def test_authcode_empty_scope(self):
        self.client.login(username='testuser', password='test')
        # 1) RO UA opens authorization endpoint
        endpoint_path = '/authorize/'
        args = dict(
            response_type='code',
            client_id='1234',
            redirect_uri='http://example.com/destination?par1=val1',
            scope='',
            state='abcdef1234567890'
        )
        response = self.client.get(
            endpoint_path,
            data=args,
            HTTP_REFERER='http://example.com/source/',
        )

        # 2) RO grants authorization
        response = self.client.post(
            endpoint_path,
            data=args,
            HTTP_REFERER=endpoint_path,
        )
        self.assertEqual(response.status_code,
                          302,
                          'grant endpoint must redirect to redirect_uri')
        o = urlparse(response['Location'])
        self.assertEqual(o.scheme, 'http')
        self.assertEqual(o.netloc, 'example.com')
        self.assertEqual(o.path, '/destination')
        self.assertEqual(o.fragment, '')
        redirect_args = parse_qs(o.query)
        self.assertEqual(redirect_args['par1'], ['val1'])
        self.assertIn('code', redirect_args)
        self.assertIn('state', redirect_args)
        self.assertEqual(redirect_args['state'], [args['state']])
        auth_code, = redirect_args['code']


class BearerAuthTestMiddleware(BearerAuthMiddleware):
    def is_oauth_request(self, request):
        return True


class MiddlewareTest(TestCase):

    def setUp(self):
        self.middleware = BearerAuthTestMiddleware()

    def test_invalid_token_padding(self):
        request = RequestFactory().get(
            '/test/',
            HTTP_AUTHORIZATION='Bearer 12345',
        )
        self.middleware.process_request(request=request)
        self.assertIsNone(request.client_id)

    def test_invalid_token_characters(self):
        request = RequestFactory().get(
            '/test/',
            HTTP_AUTHORIZATION='Bearer \x7f',
        )
        self.middleware.process_request(request=request)
        self.assertIsNone(request.client_id)

    def test_invalid_token_missing(self):
        request = RequestFactory().get(
            '/test/',
            HTTP_AUTHORIZATION='Bearer',
        )
        self.middleware.process_request(request=request)
        self.assertIsNone(request.client_id)

    def test_invalid_token_missing_header(self):
        request = RequestFactory().get(
            '/test/',
        )
        self.middleware.process_request(request=request)
        self.assertIsNone(request.client_id)

    def test_non_emitted_token(self):
        request = RequestFactory().get(
            '/test/',
            HTTP_AUTHORIZATION='Bearer 0000',
        )
        self.middleware.process_request(request=request)
        self.assertIsNone(request.client_id)


class FormsTest(TestCase):

    def test_valid_scope(self):
        scopes = [
            ('aaa bbb ccc', ['aaa', 'bbb', 'ccc']),
            ('aaa', ['aaa']),
            ('aaa aaa', ['aaa']),
            ('aaa aaa bbb', ['aaa', 'bbb']),
            ('bbb aaa ccc', ['aaa', 'bbb', 'ccc']),
            ('aaa,bbb', ['aaa,bbb']),
            ('aaa,bbb ccc', ['aaa,bbb', 'ccc']),
            ('', []),
        ]
        form_data = dict(
            grant_type='authorization_code',
            code='xxx',
            redirect_uri='http://example.com/',
            client_id='123',
        )
        for scope_arg, scope in scopes:
            form_data['scope'] = scope_arg
            form_class = make_token_form('authorization_code',
                required_fields=['scope'],
            )
            form = form_class(form_data)
            self.assertTrue(form.is_valid(),
                "scope string %r should validate" % scope_arg)
            self.assertEqual(set(form.cleaned_data['scope']),
                             set(scope),
                             "scope string %r should result "
                             "in scope set %r, not %r" %
                             (scope_arg, scope,
                                form.cleaned_data['scope']))

    def test_invalid_scope(self):
        scopes = [
            'aaa   bbb    ccc',
            'aaa\\bbb',
            '"b"',
            'a\nc',
            'a\x00b',
        ]
        form_data = dict(
            grant_type='authorization_code',
            code='xxx',
            redirect_uri='http://example.com/',
            client_id='123',
        )
        for scope_arg in scopes:
            form_data['scope'] = scope_arg
            form_class = make_token_form('authorization_code',
                required_fields=['scope'],
            )
            form = form_class(form_data)
            self.assertFalse(form.is_valid(),
                "scope string %r should result in an error" % scope_arg)
            self.assertIn('scope', form.errors)
