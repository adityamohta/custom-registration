from django.conf.urls import url, include

from .views import (
    activation,
    login_view,
    logout_view,
    new_activation_link,
    register_view,
    reset_password,
    reset_password_view,
)


urlpatterns = [
    url(r'^activate/(?P<key>.+)$', activation, name='activate'),
    url(r'^forgot-password/$', reset_password_view, name='forgot'),
    url(r'^forgot-password/(?P<key>.+)$', reset_password),
    url(r'^login/$', login_view, name='login'),
    url(r'^logout/$', logout_view, name='logout'),
    url(r'^new_activate/(?P<user_id>\d+)$', new_activation_link, name='new_activate'),
    url(r'^register/$', register_view, name='register'),
]
