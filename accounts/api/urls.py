from django.conf.urls import url
from .views import UserRegistrationAPIView, UserLoginAPIView

urlpatterns = [
    url(r'^register/', UserRegistrationAPIView.as_view(), name='register'),
    url(r'^login/', UserLoginAPIView.as_view(), name='login'),
]
