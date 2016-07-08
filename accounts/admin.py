from django.contrib import admin
from .models import UserProfile, ForgotPassword


class ForgotPasswordAdmin(admin.ModelAdmin):
    list_display = ['user', 'key_expires', ]

    class Meta:
        model = ForgotPassword


class UserProfileAdmin(admin.ModelAdmin):
    list_display = ['user', 'is_active', ]

    class Meta:
        model = UserProfile


admin.site.register(ForgotPassword, ForgotPasswordAdmin)
admin.site.register(UserProfile, UserProfileAdmin)
