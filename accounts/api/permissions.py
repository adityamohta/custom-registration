from django.contrib.auth import get_user
from rest_framework.permissions import BasePermission, SAFE_METHODS


# will be used in Future.
class IsOwnerOrReadOnly(BasePermission):
    message = 'you must be owner of this object.'

    def has_object_permission(self, request, view, obj):
        if request.method in SAFE_METHODS:
            return True
        return obj.user == get_user(request)