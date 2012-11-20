from django import forms
from django.core.exceptions import ValidationError

from fulmine.models import parse_scope

class SeparatedValuesField(forms.CharField):
    def __init__(self, *args, **kwargs):
        self.separator = kwargs.pop('separator', ' ')
        super(SeparatedValuesField, self).__init__(*args, **kwargs)

    def clean(self, value):
        if not value:
            return
        return value.split(self.separator)


class AuthorizationForm(forms.Form):
    response_type = forms.ChoiceField(
        choices=[('code', 'code'), ('token', 'token')])
    client_id = forms.CharField()
    redirect_uri = forms.CharField(required=False)
    scope = SeparatedValuesField(required=False)
    state = forms.CharField(required=False)

    def clean_scope(self):
        scope = self.cleaned_data['scope']
        return parse_scope(scope)


class TokenForm(forms.Form):
    grant_type = forms.ChoiceField(
        choices=[
            ('authorization_code', 'authorization_code'),
            ('password', 'password'),
            ('client_credentials', 'client_credentials'),
            ('refresh_token', 'refresh_token'),
        ])

    # required by authorization_code
    code = forms.CharField(required=False)
    redirect_uri = forms.CharField(required=False)
    client_id = forms.CharField(required=False)

    # required by password
    username = forms.CharField(required=False)
    password = forms.CharField(required=False)

    # required by password, client_credentials and refresh_token
    scope = SeparatedValuesField(required=False)

    # required by refresh_token
    refresh_token = forms.CharField(required=False)

    _required_on_grant_type = dict(
        authorization_code=['code'],
        password=['username', 'password', 'scope'],
        client_credentials=['scope'],
        refresh_token=['refresh_token'],
    )

    def clean_scope(self):
        scope = self.cleaned_data['scope']
        if scope:
            return parse_scope(scope)
        else:
            return []

    def clean(self):
        grant_type = self.cleaned_data.get('grant_type', None)
        if grant_type:
            required_fields = self._required_on_grant_type[grant_type]
            for field in required_fields:
                if not self.cleaned_data[field]:
                    raise ValidationError('%s is required' % field)
        return self.cleaned_data
