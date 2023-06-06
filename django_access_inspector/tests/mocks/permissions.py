from rest_framework.permissions import BasePermission


class TestOnly(BasePermission):
    message = "Only a test"

    def has_object_permission(self, request, view, obj):
        return False
