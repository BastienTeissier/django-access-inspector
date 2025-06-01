from typing import Any

from django.http import HttpRequest
from rest_framework.permissions import BasePermission
from rest_framework.views import APIView


class TestOnly(BasePermission):
    message = "Only a test"

    def has_object_permission(
        self, request: HttpRequest, view: APIView, obj: Any
    ) -> bool:
        return False
