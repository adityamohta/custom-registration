from django.conf import settings
from django.db import models
from django.utils import timezone


class UserProfile(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, related_name='user_profile')  # 1 to 1 link with Django User.
    is_active = models.BooleanField(default=False)
    activation_key = models.CharField(max_length=40)
    key_expires = models.DateTimeField(default=timezone.now()+timezone.timedelta(days=2))

    def __str__(self):
        return "%s" % self.user.username


class ForgotPassword(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, related_name='forgot_password')
    activation_key = models.CharField(max_length=40)
    key_expires = models.DateTimeField(default=timezone.now()+timezone.timedelta(minutes=15))

    def __str__(self):
        return "%s" % self.user.username
