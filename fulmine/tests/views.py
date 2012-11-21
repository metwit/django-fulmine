from django.http import HttpResponse
from django.template import RequestContext, Template

from fulmine.views import OAuth2Authorization, OAuth2Token

apps = {
    '1234': dict(
        client_id='1234',
        redirect_uri='http://example.com/destination?par1=val1',
        confidential=True,
    ),
    'confidential': dict(
        client_id='confidential',
        redirect_uri='http://example.com/destination?par1=val1',
        confidential=True,
    ),
    'public': dict(
        client_id='public',
        redirect_uri='http://example.com/destination?par1=val1',
        confidential=False,
    ),
}

auth_dialog_template = Template("""
<form method="POST" action="">
{% csrf_token %}
{{ auth_request.as_hidden_fields }}
<p>Application <strong>{{ auth_request.app.name }} is requesting
access to your data: {{ auth_request.scope }}.</p>
<input type="submit" value="Grant!">
</form>
""")

class TestAuthorization(OAuth2Authorization):
    def authorization_dialog(self, request, auth_request):
        if auth_request.errors:
            return HttpResponse(str(auth_request.errors),
                                content_type="text/plain",
                                status_code=400)
        c = RequestContext(request, dict(
                auth_request=auth_request
            ))
        return HttpResponse(auth_dialog_template.render(c))


class TestToken(OAuth2Token):
    def client_for_request(self, request, client_id):
        if 'HTTP_X_TEST_CLIENT_AUTH' in request.META:
            client = request.META['HTTP_X_TEST_CLIENT_AUTH']
            if client in apps:
                return client
            else:
                return None
        else:
            if client_id in apps:
                if apps[client_id]['confidential']:
                    return None
                else:
                    return client_id


authorize = TestAuthorization().as_view()
token = TestToken().as_view()

def protected_resource(request):
    if request.client_id:
        return HttpResponse("%s:%s" % (request.client_id,
                                       request.user.username))
    else:
        return HttpResponse("FAIL")
