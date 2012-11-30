from django import forms
from django.core.exceptions import ValidationError

from fulmine.models import parse_scope

class SeparatedValuesField(forms.CharField):
    def __init__(self, *args, **kwargs):
        self.separator = kwargs.pop('separator', ' ')
        super(SeparatedValuesField, self).__init__(*args, **kwargs)

    def clean(self, value):
        if not value:
            return []
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


def clean_scope(form):
    scope = form.cleaned_data['scope']
    return parse_scope(scope)

def make_token_form(grant_type, required_fields=[], optional_fields=[],
                    django_fields={}):

    class_dict = dict()

    for field_name in optional_fields:
        if field_name == 'scope':
            field = SeparatedValuesField(required=False)
        else:
            field = forms.CharField(required=False)

        class_dict[field_name] = field

    for field_name in required_fields:
        if field_name == 'scope':
            field = SeparatedValuesField(required=True)
        else:
            field = forms.CharField(required=True)

        class_dict[field_name] = field

    for field_name, field in django_fields.iteritems():
        class_dict[field_name] = field

    class_dict['clean_scope'] = clean_scope

    cls = type('%sTokenForm' % grant_type,
               (forms.Form, ),
               class_dict
              )

    return cls

AuthorizationCodeTokenForm = make_token_form('authorization_code',
    required_fields=[
        'code',
    ],
    optional_fields=[
        'redirect_uri',
        'client_id',
        'scope',
    ]
)

PasswordTokenForm = make_token_form('password',
    required_fields=[
        'username',
        'password',
        'scope',
    ]
)

ClientCredentialsTokenForm = make_token_form('client_credentials',
    required_fields=['scope'],
)

RefreshTokenTokenForm = make_token_form('refresh_token',
    required_fields=['refresh_token'],
    optional_fields=['scope']
)
