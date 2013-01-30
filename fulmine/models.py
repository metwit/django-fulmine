from datetime import timedelta
import re
from urllib import urlencode
from urlparse import parse_qs, urlparse, urlunparse

from django.conf import settings
from django.contrib.auth import (
    SESSION_KEY as CONTRIB_AUTH_SESSION_KEY,
    BACKEND_SESSION_KEY as CONTRIB_AUTH_BACKEND_SESSION_KEY,
)
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.db import models
from django.utils.importlib import import_module

from fulmine.settings import *
from fulmine.timeutils import utcnow
from fulmine.tokens import parse_bearer, random_b64, Token

try:
    from south.modelsinspector import add_introspection_rules
    add_introspection_rules([], ["^fulmine\.models\.SeparatedValuesField"])
except ImportError:
    # no south, just carry on
    pass


def new_auth_code():
    return random_b64(AUTH_CODE_BYTES)

def new_access_token():
    return Token(ACCESS_TOKEN_BYTES)

def new_b64_access_token():
    return unicode(new_access_token())

def auth_code_expires():
    now = utcnow()
    delta = timedelta(seconds=AUTH_CODE_EXPIRE_SECONDS)
    return now + delta

def build_access_token(scope, expires_in, client_id, deploy_id='',
                       user_id=None, auth_backend=None, grant_id=None):
    access_token = new_access_token()
    session_key, secret = parse_bearer(access_token,
                                       SESSION_KEY_BYTES)
    session = get_django_session(session_key)
    session.clear() # otherwise Django would overwrite the session_hey
    session['_fulmine_secret'] = secret
    session['_fulmine_client_id'] = client_id
    session['_fulmine_deploy_id'] = deploy_id
    if user_id:
        session[CONTRIB_AUTH_SESSION_KEY] = user_id
        session[CONTRIB_AUTH_BACKEND_SESSION_KEY] = auth_backend
    session['_fulmine_scope'] = scope
    session['_fulmine_revoked'] = False
    session['_fulmine_grant'] = grant_id
    session.set_expiry(timedelta(seconds=expires_in))
    session.save(must_create=True)
    return unicode(access_token)


class SeparatedValuesField(models.TextField):
    __metaclass__ = models.SubfieldBase

    def __init__(self, *args, **kwargs):
        self.separator = kwargs.pop('separator', ' ')
        super(SeparatedValuesField, self).__init__(*args, **kwargs)

    def to_python(self, value):
        if not value:
            return []
        if isinstance(value, list):
            return value
        return value.split(self.separator)

    def get_db_prep_value(self, value, connection, prepared=False):
        if not value:
            return ''
        return self.separator.join([unicode(s) for s in value])

    def value_to_string(self, obj):
        value = self._get_val_from_obj(obj)
        return self.get_db_prep_value(value)


class AuthorizationGrantManager(models.Manager):
    def active(self):
        return self.filter(revoked=False)

    def grant_or_update(self, client_id, auth_backend, user, scope):
        obj, created = self.get_or_create(
            client_id=client_id,
            user=user,
            defaults=dict(auth_backend=auth_backend, scope=scope),
        )

        if not created:
            if set(scope) - set(obj.scope):
                obj.scope = list(set(scope) | set(obj.scope))
                obj.save()

        return obj


class AuthorizationGrant(models.Model):
    client_id = models.CharField(max_length=CLIENT_ID_LENGTH, db_index=True)
    auth_backend = models.CharField(max_length=80)
    user = models.ForeignKey(User, db_index=True)
    scope = SeparatedValuesField(max_length=SCOPE_LENGTH, blank=True)
    revoked = models.BooleanField(default=False)

    objects = AuthorizationGrantManager()

    class Meta:
        unique_together = ('client_id', 'user')

    def new_auth_code(self):
        temp = TemporaryGrant()
        temp.grant = self
        return temp

    def emit_token(self, expires_in, emit_refresh=True,
                   scope=None, deploy_id=''):
        """
        Creates, saves and returns an AccessToken and a RefreshToken.
        The grant will be consumed after the emission.
        """
        if self.revoked:
            raise Exception('revoked grant can\'t emit tokens')

        if scope:
            token_scope = list(set(scope) & set(self.scope))
        else:
            token_scope = self.scope

        access_token_text = build_access_token(
            client_id=self.client_id,
            deploy_id=deploy_id,
            expires_in=expires_in,
            scope=token_scope,
            user_id=self.user.id,
            auth_backend=self.auth_backend,
            grant_id=self.pk,
        )


        if emit_refresh:
            refresh_token = RefreshToken()
            refresh_token.grant = self
            refresh_token.deploy_id = deploy_id
            refresh_token.scope = scope
            refresh_token.save()
            refresh_token_text = refresh_token.token
        else:
            refresh_token_text = None

        return access_token_text, refresh_token_text


class TemporaryGrantManager(models.Manager):
    def authorized(self, auth_code, redirect_uri, client_id, deploy_id=''):
        return self.filter(
            consumed=False,
            expires__gt=utcnow(),
            auth_code=auth_code,
            redirect_uri=redirect_uri,
            grant__client_id=client_id,
            deploy_id=deploy_id,
        )


class TemporaryGrant(models.Model):
    auth_code = models.CharField(max_length=AUTH_CODE_LENGTH,
                                 default=new_auth_code,
                                 primary_key=True)
    expires = models.DateTimeField(default=auth_code_expires)
    grant = models.ForeignKey(AuthorizationGrant)
    scope = SeparatedValuesField(max_length=SCOPE_LENGTH, blank=True)
    deploy_id = models.CharField(max_length=DEPLOY_ID_LENGTH, blank=True)
    expires = models.DateTimeField(default=auth_code_expires)
    state = models.CharField(max_length=300, blank=True)
    redirect_uri = models.CharField(max_length=400)
    consumed = models.BooleanField(default=False)

    objects = TemporaryGrantManager()

    def emit_token(self, expires_in, emit_refresh=True):
        if self.consumed:
            raise Exception('consumed grant can\'t emit tokens')

        self.consumed = True
        self.save()

        return self.grant.emit_token(
            expires_in=expires_in,
            deploy_id=self.deploy_id,
            scope=self.scope,
            emit_refresh=emit_refresh
        )


class RefreshTokenManager(models.Manager):
    def refreshable(self, refresh_token, deploy_id=''):
        return self.filter(
            revoked=False,
            token=refresh_token,
            deploy_id=deploy_id,
        )


class RefreshToken(models.Model):
    token = models.CharField(max_length=ACCESS_TOKEN_LENGTH,
                                     default=new_b64_access_token,
                                     primary_key=True)
    deploy_id = models.CharField(max_length=DEPLOY_ID_LENGTH, blank=True)
    grant = models.ForeignKey(AuthorizationGrant)
    scope = SeparatedValuesField(max_length=SCOPE_LENGTH, blank=True)
    revoked = models.BooleanField(default=False)

    objects = RefreshTokenManager()

    def emit_token(self, expires_in, emit_refresh=False):
        if self.revoked:
            raise Exception('revoked refresh token can\'t be used')

        if emit_refresh:
            self.revoked = True
            self.save()

        return self.grant.emit_token(
            expires_in=expires_in,
            deploy_id=self.deploy_id,
            scope=self.scope,
            emit_refresh=emit_refresh,
        )

class AuthorizationRequest(object):
    def __init__(self, response_type, client_id,
                 redirect_uri, scope, state):
        self._client_id = None
        self._redirect_uri = None

        self.errors = []
        self.response_type = response_type
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.scope = scope
        self.state = state

    @property
    def client_id(self):
        return self._client_id

    @client_id.setter
    def client_id(self, value):
        self._client_id = value
        self.validate()

    @property
    def redirect_uri(self):
        return self._redirect_uri

    @redirect_uri.setter
    def redirect_uri(self, value):
        self._redirect_uri = value
        self.validate()

    def validate(self):
        self.errors = []
        if self.response_type not in ['code', 'token']:
            self.errors.append('invalid response_type')
        if self.client_id is None:
            self.errors.append('invalid client_id')
            self.errors.append('invalid redirect_uri')
        else:
            if not self.validate_redirect_uri():
                self.errors.append('invalid_redirect_uri')

    def validate_redirect_uri(self):
        # TODO: do some solid check
        return True

    def as_hidden_fields(self):
        from django.utils.html import escape
        fields = dict()
        fields['response_type'] = self.response_type
        fields['redirect_uri'] = self.redirect_uri
        fields['scope'] = self.scope
        fields['state'] = self.state
        fields['client_id'] = self.client_id
        return '\n'.join(
            """<input type="hidden" name="{}" value="{}">""".format(
                escape(name),
                escape(value),
            )
            for name, value in fields.iteritems()
        )

    def grant(self, request):
        grant = AuthorizationGrant.objects.grant_or_update(
            client_id=self.client_id,
            user=request.user,
            auth_backend=request.session[CONTRIB_AUTH_BACKEND_SESSION_KEY],
            scope=self.scope,
        )
        self.grant_obj = grant
        return grant

    def code_redirect(self):
        temp = self.grant_obj.new_auth_code()
        temp.state = self.state
        temp.redirect_uri = self.redirect_uri
        #temp.deploy_id = self.deploy_id
        temp.scope = self.scope
        temp.save()

        o = urlparse(self.redirect_uri)
        query = parse_qs(o.query)
        query['code'] = temp.auth_code
        query['state'] = self.state
        new_query = urlencode(query, doseq=True)
        new_uri = urlunparse((
            o.scheme,
            o.netloc,
            o.path,
            o.params,
            new_query,
            None
        ))
        return new_uri

    def token_redirect(self, expires_in):
        o = urlparse(self.redirect_uri)

        token, refresh = self.grant_obj.emit_token(
            expires_in=expires_in,
            scope=self.scope,
            emit_refresh=False,
        )
        params = dict()
        params['access_token'] = token
        params['token_type'] = 'bearer'
        params['expires_in'] = expires_in
        params['scope'] = self.scope
        params['state'] = self.state
        fragment = urlencode(params, doseq=True)
        new_uri = urlunparse((
            o.scheme,
            o.netloc,
            o.path,
            o.params,
            o.query,
            fragment))
        return new_uri


def get_django_session(session_key):
    engine = import_module(settings.SESSION_ENGINE)
    return engine.SessionStore(session_key)

scope_re = re.compile(r'^[!#-[\]-~]+$')

def parse_scope(scope):
    if any(scope_re.match(s) is None for s in scope):
        raise ValidationError('invalid scope')
    return scope
