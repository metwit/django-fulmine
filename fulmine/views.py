import json
import re

from django.http import HttpResponse, HttpResponseBadRequest, HttpResponseRedirect
from django.views.decorators.csrf import csrf_exempt, csrf_protect
from django.views.decorators.http import require_http_methods

from fulmine.forms import (
    AuthorizationForm,
    AuthorizationCodeTokenForm,
    PasswordTokenForm,
    ClientCredentialsTokenForm,
    RefreshTokenTokenForm,
)
from fulmine.models import (
    AuthorizationGrant,
    AuthorizationRequest,
    TemporaryGrant,
    RefreshToken,
    build_access_token,
)

import logging
logger = logging.getLogger('django_fulmine')

class JsonResponse(HttpResponse):
    def __init__(self, json_dict):
        content = json.dumps(json_dict)
        super(JsonResponse, self).__init__(content,
                                           content_type='application/json')


class OAuth2Error(HttpResponseBadRequest):

    def __init__(self, error, description=None, uri=None):
        d = dict(error=error)
        if description:
            d['error_description'] = description
        if uri:
            d['error_uri'] = uri
        content = json.dumps(d)
        super(OAuth2Error, self).__init__(content,
                                          content_type='application/json')


class OAuth2Authorization(object):
    default_implicit_expires_in = 3600

    def as_view(self):
        @require_http_methods(['GET', 'POST'])
        @csrf_protect
        def OAuth2Authorization_view(*args, **kwargs):
            try:
                return self.call_view(*args, **kwargs)
            except Exception as ex:
                logger.exception(ex)
                raise
        return OAuth2Authorization_view

    def call_view(self, request):
        if request.method == 'GET':
            form = AuthorizationForm(request.GET)
        else:
            form = AuthorizationForm(request.POST)

        if form.is_valid():
            uri = form.cleaned_data['redirect_uri']
            authreq = AuthorizationRequest(
                response_type=form.cleaned_data['response_type'],
                client_id=form.cleaned_data['client_id'],
                redirect_uri=uri,
                scope=form.cleaned_data['scope'],
                state=form.cleaned_data['state'])
            if request.method == 'GET':
                return self._dialog(request, authreq)
            else:
                return self._grant(request, authreq)
        else:
            return HttpResponseBadRequest()
    
    def _dialog(self, request, authreq):
        return self.authorization_dialog(
            request=request,
            auth_request=authreq,
        )

    def _grant(self, request, authreq):
        authreq.grant(request)
        if authreq.response_type == 'code':
            return self._do_code_redirect(request, authreq)
        elif authreq.response_type == 'token':
            return self._do_token_redirect(request, authreq)

    def _do_code_redirect(self, request, authreq):
        authreq.grant_obj.save()
        uri = authreq.code_redirect()
        return HttpResponseRedirect(uri)

    def _do_token_redirect(self, request, authreq):
        expires_in = self.expires_in(authreq)
        uri = authreq.token_redirect(expires_in)
        return HttpResponseRedirect(uri)

    def expires_in(self, auth_request):
        """
        Override to specify the expiration time in seconds of access tokens
        emitted with implicit (url fragment redirection) grant type.

        If not overriden returns self.default_implicit_expires_in
        (default: 3600).
        """
        return self.default_implicit_expires_in


class OAuth2Token(object):
    default_expires_in = 3600

    extra_grant_types = {}
    grant_types = {
        'authorization_code': AuthorizationCodeTokenForm,
        'password': PasswordTokenForm,
        'client_credentials': ClientCredentialsTokenForm,
        'refresh_token': RefreshTokenTokenForm,
    }

    def __init__(self):
        self.grant_types = self.__class__.grant_types.copy()
        self.grant_types.update(self.__class__.extra_grant_types)

    def as_view(self):
        @require_http_methods(['POST'])
        @csrf_exempt
        def OAuth2Token_view(*args, **kwargs):
            try:
                return self.call_view(*args, **kwargs)
            except Exception as ex:
                logger.exception(ex)
                raise
        return OAuth2Token_view

    def call_view(self, request):
        grant_type = request.POST.get('grant_type', None)
        if grant_type not in self.grant_types:
                return OAuth2Error('unsupported_grant_type')

        form = self.grant_types[grant_type](request.POST)
        if form.is_valid():
            method = getattr(self, '_%s' % grant_type)
            token_response = method(request, form)
            if not isinstance(token_response, HttpResponse):
                response = JsonResponse(token_response)
                # rfc6749 requires token responses not to be cached
                response['Cache-control'] = 'no-store'
                response['Pragma'] = 'no-cache'
                return response
            else:
                return token_response
        else:
            return OAuth2Error('invalid_request')

    def _authorization_code(self, request, form):
        auth_code = form.cleaned_data['code']
        redirect_uri = form.cleaned_data['redirect_uri']
        client_id = self.client_for_request(request,
                                            form.cleaned_data['client_id'])

        if not client_id:
            return OAuth2Error('invalid_client')

        try:
            auth = TemporaryGrant.objects.authorized(
                auth_code=auth_code,
                redirect_uri=redirect_uri,
                client_id=client_id,
            ).get()
        except TemporaryGrant.DoesNotExist:
            return OAuth2Error('invalid_grant')

        expires_in = self.expires_in(auth.grant)
        access_token, refresh_token = auth.emit_token(expires_in)
        return dict(
            access_token=access_token,
            token_type='bearer',
            expires_in=expires_in,
            refresh_token=refresh_token,
            scope=auth.scope,
        )

    def _password(self, request, form):
        client_id = self.client_for_request(request, None)

        if not client_id:
            return OAuth2Error('invalid_client')

        scope = self.limit_scope(client_id, form.cleaned_data['scope'])

        from django.contrib.auth import authenticate
        user = authenticate(username=form.cleaned_data['username'],
                            password=form.cleaned_data['password'])
        if not user:
            raise OAuth2Error('invalid_grant')

        grant = AuthorizationGrant.objects.grant_or_update(
            user=user,
            client_id=client_id,
            auth_backend=user.backend,
            scope=scope,
        )

        expires_in = self.expires_in(grant)
        access_token, refresh_token = grant.emit_token(
            expires_in=expires_in,
            scope=scope,
            emit_refresh=True,
        )

        return dict(
            access_token=access_token,
            token_type='bearer',
            expires_in=expires_in,
            refresh_token=refresh_token,
            scope=scope,
        )

    def _client_credentials(self, request, form):
        client_id = self.client_for_request(request, None)

        if not client_id:
            return OAuth2Error('invalid_client')

        scope = self.limit_scope(client_id, form.cleaned_data['scope'])

        expires_in = self.expires_in(None)

        access_token = build_access_token(
            client_id=client_id,
            expires_in=expires_in,
            scope=scope,
        )

        return dict(
            access_token=access_token,
            token_type='bearer',
            expires_in=expires_in,
            refresh_token=None,
            scope=scope,
        )

    def _refresh_token(self, request, form):
        refresh_token = form.cleaned_data['refresh_token']

        try:
            refresh = RefreshToken.objects.refreshable(
                refresh_token=refresh_token,
            ).select_related('grant').get()
        except RefreshToken.DoesNotExist:
            return OAuth2Error('invalid_grant')

        client_id = refresh.grant.client_id
        scope = self.limit_scope(client_id, form.cleaned_data['scope'])

        if set(scope) - set(refresh.scope):
            # client is requesting a scope not originally granted 
            return OAuth2Error('invalid_scope')

        if set(scope) < set(refresh.scope):
            refresh.scope = scope

        expires_in = self.expires_in(refresh.grant)
        access_token, refresh_token = refresh.emit_token(expires_in)
        return dict(
            access_token=access_token,
            token_type='bearer',
            expires_in=expires_in,
            refresh_token=refresh_token,
            scope=scope,
        )

    def client_for_request(self, request, client_id):
        """
        Override to implement client authentication. client_id parameter
        is the client_id as supplied by the client in the access token
        request.

        If the client is authenticated (confidential client), client_id
        parameter can be ignored and the method must return client's client_id,
        or None if authentication failed.

        If no client is authenticated (public client), client_id parameter
        refers to the client which requested the token. The method must then
        return client_id if it is valid, None otherwise.

        If the client registered as a confidential client then it is required
        to always use authentication and can not be identified like a public
        client. Therefore if the client_id parameter specifies a confidential
        client and the request is not authenticated then this method must
        return None.

        Examples:
        1) client_id specifies a valid public client
        >>> client_id = 'public_12345'
        >>> obj.client_for_request(request, client_id)
        'public_12345'

        2) client_id specifies a confidential client and request is
           not authenticated
        >>> client_id = 'confidential_99999'
        >>> obj.client_for_request(request, client_id)
        None

        3) request is authenticated with valid client credentials
        >>> obj.client_for_request(request, 'anything')
        'confidential_99999'

        Note that as of RFC 6749 (2.3.1) if the client was issued a client
        password then your implementation MUST support the HTTP Basic
        authentication scheme. For more information about client authentication
        read RFC 6749 (2.3. Client Authentication).
        """
        raise NotImplementedError()

    def limit_scope(self, client_id, scope):
        return scope

    def expires_in(self, grant):
        """
        Override to specify the expiration time in seconds of emitted
        access tokens.

        If not overriden returns self.default_expires_in (default: 3600).
        """
        return self.default_expires_in


client_id_re = re.compile("""^
    (?P<client_id>[\x20-\x39\x3b-\x7e]+)     # mandatory client_id
    (?:                                      # optional colon separated deploy_id
        :
        (?P<deploy_id>[\x20-\x39\x3b-\x7e]+)
    )?$""",
    re.VERBOSE)

def parse_client_id(client_id):
    m = client_id_re.match(client_id)
    if m:
        return m.groups() # client_id, group_id
    else:
        return None
