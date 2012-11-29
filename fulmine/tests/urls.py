from django.conf.urls.defaults import *

urlpatterns = patterns('fulmine.tests.views',
    url(r'^authorize/$', 'authorize'),
    url(r'^token/$', 'token'),
    url(r'^resource/$', 'protected_resource'),
    url(r'^scope/$', 'scope_resource'),
)
