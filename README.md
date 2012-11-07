django-fulmine
==============

Django OAuth 2.0 ([RFC 6749](http://self-issued.info/docs/rfc6749.html))
pluggable implementation.

django-fulmine provides bearer token authentication ([RFC 6750]
(http://self-issued.info/docs/rfc6749.html)). Its implementation is based
on Django sessions (as provided by django.contrib.sessions).

Important note
--------------

At this stage this implementation is rather incomplete. No support
for scopes is provided, and redirect_uri is not validated upon authorization.
This would allow a number of well known attacks. This project is planning to
provide complete support for the missing features in the near future.

Meanwhile this implementation is provided to the public for testing and review
purposes. If you plan to use this project in production please contact me at
davide@metwit.com.

Quick start
-----------

Before starting you should have installed `fulmine` in your Python path for
your Django project. For example:

    pip install django-fulmine

Setting up django-fulmine requires overriding a middleware and a couple views.
You might want to create a package (or an app) for your custom OAuth 2.0 code.
During this steps we will assume you have a package called `myauth` where new
files can be added.

### 1. **Install app**
Add `fulmine` to your Django project installed apps in settings.py:

     INSTALLED_APPS = (
         ...
         'fulmine',
     )

### 2. **Subclass middleware**
Create a subclass of `fulmine.middleware.BearerAuthMiddleware` implementing
an `is_oauth_request` method. Your `myauth/middleware.py` might look like
this:

     from fulmine.middleware import BearerAuthMiddleware

     class MyAuthMiddleware(BearerAuthMiddleware):

         def is_oauth_request(self, request):
             return request.path.startswith('/api/')

`is_oauth_request()` basically should return True when the request is for
an OAuth protected resource, False otherwise. OAuth protected resources
are those which require a valid access token to access, and are denied
access otherwise.

Keep in mind that at this point you don't have access to the view function
because this method is called before url resolution. Sessions aren't
available as well, as this middleware replaces SessionMiddleware.

### 3. **Install middleware**
Replace `SessionMiddleware` with your new middleware in settings.py. For
example if you had:

     MIDDLEWARE_CLASSES = (
      'django.middleware.common.CommonMiddleware',
      'django.contrib.sessions.middleware.SessionMiddleware',
      'django.middleware.csrf.CsrfViewMiddleware',
      'django.contrib.auth.middleware.AuthenticationMiddleware',
      'django.contrib.messages.middleware.MessageMiddleware',
     )

you can replace it with:

     MIDDLEWARE_CLASSES = (
      'django.middleware.common.CommonMiddleware',
      'myauth.middleware.MyAuthMiddleware',
      'django.middleware.csrf.CsrfViewMiddleware',
      'django.contrib.auth.middleware.AuthenticationMiddleware',
      'django.contrib.messages.middleware.MessageMiddleware',
     )

The default implementation of `BearerAuthMiddleware` works exactly like
SessionMiddleware for all requests for which `is_oauth_request` returns
False. So you can have traditional session management and authentication
on your site for some requests, and access token based authentication for
your API calls.

### 4. **Authorization endpoint**
Create a subclass of `fulmine.views.OAuth2Authorization`. This view is
going to be called whenever a client redirects to your application to
request authorization.

Most of what is needed to comply to OAuth 2.0 standard is already provided
by django-fulmine. You only have to override one view method,
`authorization_dialog`. Implementation of this method will likely be the
most complex task of your OAuth setup, as it has several fundamental
responsibilities:

1. Show an interface to your users that clearly identifies your service,
   the client that has requested authorization and the permission it has
   requested.

2. Authenticate your users if they aren't already logged on your site when
   authorization is requested.

3. Carry all parameters needed for OAuth dance to complete to the next view
   in the flow.

An implementation skeleton is provided:

     class MyAuthAuthorization(OAuth2Authorization):
         
         def authorization_dialog(self, request, auth_request):
             if auth_request.errors:
                 # TODO: show a generic error message for a wrong
                 # request. Unless you're debugging, don't display
                 # any assumptions about the error or its solution.
             elif request.user.is_anonymous:
                 # TODO: display a login page. After login the user
                 # must be redirected to the same URL as this request.
             else:
                 # TODO: show a grant request page for the application
                 # that requested authorization.

When a user makes a GET request on the authorization endpoint
(e.g http://example.com/authorize/) this method will be called. It must
return a HttpResponse object (or one of its subclasses) like any Django
view.

To grant permission the user is ultimately expected to click on a button
that will submit a POST request to the same endpoint. The submitted form
data must include Django CSRF token and all mandatory fields of the OAuth
2.0 authorization request: `client_id`, `response_type`, `redirect_uri`,
`scope` and `state`. All these parameters are included with the same name
in the `auth_request` object that is passed to the method. A convenience
method `auth_request.as_hidden_fields()` is included that returns the HTML
to include all required parameters as hidden input forms.

You will most likely want to use a couple of this parameters at this point:
`client_id` as it identifies the app that is requesting permission, and
`scope`, a space separated list of the requested scopes. Note that you
don't need to authenticate the requesting app at this point.

### 5. **Token endpoint**
Create a subclass of `fulmine.views.OAuth2Token`. This view is going to
be called directly from the client to obtain an access token after
authorization has been granted (i.e. during authorization code flow) or
to start 2-legged authorization flows.

You are required to implement only one method in this class,
`client_for_request`. Its implementation usually is fairly simple, but it
needs to deal with a number of different cases. See the "client_for_request
method" section for details. Basically it must validate a given `client_id`
and authenticate the request if the client needs authentication (i.e. it is
a _confidential client_). It must return the client_id itself, or None if
the given client_id is invalid or the client is not authenticated.

It might follow this pattern:

     class MyAuthToken(OAuth2Token):

         def client_for_request(self, request, client_id):
             if request is authenticated:
                 if successful authentication:
                     return authenticated client_id
                 else:
                     return None
             else:
                 try:
                     return App.objects.get(client_id=client_id).client_id
                 except App.DoesNotExist:
                     return None

Client authentication is up to the implementation and not part of OAuth 2.0
specifications. The only requirement is to support HTTP Basic authorization
scheme whenever a client is issued username/password-style credentials.

### 6. **Endpoints URLs**
Make the two views accessible from your Django project URL configuration.
Use the `as_view()` method to get the view callables to use in your
configuration. For example:

     urlpatterns = patterns('',
         ...
         url(r'^authorize/$', myauth.MyAuthAuthorize().as_view()),
         url(r'^token/$', myauth.MyAuthToken().as_view()),
     )

Make sure your `is_oauth_request()` (as defined in step 2) returns False for
all request directed to this URLs and you're done!


After the set-up is done you can use authentication as usual in your views.
`request.user` will be the user who had granted the permission.
`request.client_id` will be the identifier of the app, or None if the request
is not successfully authenticated.


client_for_request method
-------------------------

In order to provide client identification and/or authentication you must
override this method of the OAuth2Token class.

    def client_for_request(self, request, client_id):
        # return a client_id

* `self` object includes no meaningful state and can be ignored.
* `request` is the request object provided by Django.
* `client_id` parameter is the `client_id` as supplied by the client in the
access token request.

If the client is authenticated (it is therefore a _confidential client_),
`client_id` parameter can be ignored and the method must return client's
`client_id`, or None if authentication failed.

If no client is authenticated (it is a _public client_, like a JavaScript
client or a native application), `client_id` parameter refers to the client
which requested the token. The method must then return `client_id` if it is
valid, None otherwise.

If the client registered as a confidential client then it is required
to always use authentication and can not be identified like a public
client. Therefore if the `client_id` parameter specifies a confidential
client and the request is not authenticated then this method must
return None.

Examples:

1.  `client_id` specifies a valid public client

        >>> client_id = 'public_12345'
        >>> obj.client_for_request(request, client_id)
        'public_12345'

2.  `client_id` specifies a confidential client and request is
    not authenticated

        >>> client_id = 'confidential_99999'
        >>> obj.client_for_request(request, client_id)
        None

3. request is authenticated with valid client credentials

        >>> obj.client_for_request(request, 'anything')
        'confidential_99999'

Note that as of RFC 6749 ([2.3.1]
(http://self-issued.info/docs/rfc6749.html#client-password)) if the client was
issued a client password then your implementation MUST support the HTTP Basic
authentication scheme. For more information about client authentication
read RFC 6749 ([2.3 Client Authentication]
(http://self-issued.info/docs/rfc6749.html#client-authentication)).


Known issues
------------

Don't use this software in production. It's an incomplete implementation and
offers very partial security at this stage.

Copyright and license
---------------------

django-fulmine is an open source project. It is provided under "New BSD
License" terms. Refer to the LICENSE file included in the distribution.

Copyright (c) 2012, Metwit Ltd
All rights reserved.
