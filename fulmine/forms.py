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

    def _required_on_grant_types(field, types):
        def clean_FIELD(self):
            if self.cleaned_data['grant_type'] in types:
                if not self.cleaned_data[field]:
                    raise ValidationError('%s is required' % field)
            return self.cleaned_data[field]
        return clean_FIELD

    clean_code = _required_on_grant_types('code', ['authorization_code'])
    clean_username = _required_on_grant_types('username', ['password'])
    clean_password = _required_on_grant_types('password', ['password'])
    _pre_clean_scope = _required_on_grant_types('scope', ['password', 'client_credentials'])
    clean_refresh_token = _required_on_grant_types('refresh_token', ['refresh_token'])

    def clean_scope(self):
        scope = self._pre_clean_scope()
        return parse_scope(scope)
