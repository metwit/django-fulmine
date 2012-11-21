import time

from django.conf import settings
from django.utils.cache import patch_vary_headers
from django.utils.http import cookie_date

from fulmine.models import get_django_session
from fulmine.settings import *
from fulmine.tokens import parse_authorization, parse_bearer

class BearerAuthMiddleware(object):
    def is_oauth_request(self, request):
        """
        Return True if request is for a resource that requires
        OAuth2 authentication, False otherwise.
        """
        raise NotImplementedError()

    def authenticate_access_token(self, token):
        session_key, secret = parse_bearer(token,
                                           SESSION_KEY_BYTES)
        session = get_django_session(session_key)
        session.load()
        stored_secret = session.get('_fulmine_secret', None)
        if stored_secret != secret:
            # token does not exist
            return None, None
        client_id = session.get('_fulmine_client_id', None)
        deploy_id = session.get('_fulmine_deploy_id', None)
        return client_id, session

    def process_request(self, request):
        if self.is_oauth_request(request):
            return self._token_process_request(request)
        else:
            return self._cookie_process_request(request)

    def _cookie_process_request(self, request):
        # same as django.contrib.sessions
        session_key = request.COOKIES.get(settings.SESSION_COOKIE_NAME, None)
        request.session = get_django_session(session_key)

    def _token_process_request(self, request):
        authorization = request.META.get('HTTP_AUTHORIZATION', '')
        token = parse_authorization(authorization)
        request.has_bearer = token is not None

        if token is None:
            client_id = None
            session = None
        else:
            client_id, session = self.authenticate_access_token(token)

        request.client_id = client_id
        if client_id is None:
            request.has_bearer = False

        if session:
            request.permissions = set(session['_fulmine_scope'])
            # This is an active session and we can use it like
            # a session provided by django.contrib.sessions,
            # and actually persist it.
            request.session = session
            request.session.dont_persist = False
        else:
            request.permissions = None
            # We're creating a new session because most Django
            # apps expect one, but there is no associated user
            # so we don't need to actually persist it.
            request.session = get_django_session(None)
            request.session.dont_persist = True

    def process_response(self, request, response):
        if self.is_oauth_request(request):
            return self._token_process_response(request, response)
        else:
            return self._cookie_process_response(request, response)

    def _cookie_process_response(self, request, response):
        """
        If request.session was modified, or if the configuration is to save the
        session every time, save the changes and set a session cookie.
        """
        # same as django.contrib.sessions
        try:
            accessed = request.session.accessed
            modified = request.session.modified
        except AttributeError:
            pass
        else:
            if accessed:
                patch_vary_headers(response, ('Cookie',))
            if modified or settings.SESSION_SAVE_EVERY_REQUEST:
                if request.session.get_expire_at_browser_close():
                    max_age = None
                    expires = None
                else:
                    max_age = request.session.get_expiry_age()
                    expires_time = time.time() + max_age
                    expires = cookie_date(expires_time)
                # Save the session data and refresh the client cookie.
                request.session.save()
                response.set_cookie(settings.SESSION_COOKIE_NAME,
                        request.session.session_key, max_age=max_age,
                        expires=expires, domain=settings.SESSION_COOKIE_DOMAIN,
                        path=settings.SESSION_COOKIE_PATH,
                        secure=settings.SESSION_COOKIE_SECURE or None,
                        httponly=settings.SESSION_COOKIE_HTTPONLY or None)
        return response

    def _token_process_response(self, request, response):
        try:
            accessed = request.session.accessed
            modified = request.session.modified
        except AttributeError:
            pass
        else:
            if accessed:
                patch_vary_headers(response, ('Authorization',))
            if modified or settings.SESSION_SAVE_EVERY_REQUEST:
                if not request.session.dont_persist:
                    request.session.save()
        return response
