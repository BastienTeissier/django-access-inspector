import io
import json  # Added import for json
import os
import unittest.mock
from typing import Any

from django.contrib.auth.decorators import login_required
from django.core.management import call_command
from django.core.management.base import CommandError  # Added CommandError
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.test import TestCase, override_settings  # Added override_settings
from django.urls import path
from django.views import View


# Custom comparison that handles lists by converting them to sets (order insensitive)
def compare_nested_structures(a: Any, b: Any) -> bool:
    if isinstance(a, dict) and isinstance(b, dict):
        if a.keys() != b.keys():
            return False
        return all(bool(compare_nested_structures(a[k], b[k])) for k in a.keys())
    elif isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            return False
        # For lists that contain simple values like strings, convert to sets
        if all(isinstance(x, str) for x in a) and all(isinstance(x, str) for x in b):
            return set(a) == set(b)
        # For lists of complex objects, try comparing all elements
        return all(any(bool(compare_nested_structures(x, y)) for y in b) for x in a)
    else:
        return bool(a == b)


# Mock Views
def function_based_view(request: HttpRequest) -> HttpResponse:
    return HttpResponse("Function-based view")


class ClassBasedView(View):
    def get(self, request: HttpRequest) -> HttpResponse:
        return HttpResponse("Class-based view")


class AuthenticatedView(View):
    permission_classes = ["IsAuthenticated"]

    def get(self, request: HttpRequest) -> HttpResponse:
        return HttpResponse("Authenticated view")


class TokenAuthenticatedView(View):
    authentication_classes = ["TokenAuthentication"]

    def get(self, request: HttpRequest) -> HttpResponse:
        return HttpResponse("Token authenticated view")


class MixedAuthView(View):
    permission_classes = ["IsAuthenticated"]
    authentication_classes = ["TokenAuthentication"]

    def get(self, request: HttpRequest) -> HttpResponse:
        return HttpResponse("Mixed auth view")


class AdminView(View):
    model_admin = True  # Simulate an admin view

    def get(self, request: HttpRequest) -> HttpResponse:
        return HttpResponse("Admin view")


@login_required
def unchecked_view(request: HttpRequest) -> JsonResponse:
    return JsonResponse({"data": []})


# URL Patterns
urlpatterns = [
    path("function/", function_based_view, name="function_view"),
    path("class/", ClassBasedView.as_view(), name="class_view"),
    path("authenticated/", AuthenticatedView.as_view(), name="authenticated_view"),
    path("token/", TokenAuthenticatedView.as_view(), name="token_view"),
    path("mixed/", MixedAuthView.as_view(), name="mixed_view"),
    path("admin_view/", AdminView.as_view(), name="admin_view"),
    path("unchecked/", unchecked_view, name="toto_unchecked_view"),
]


# Test Case
class InspectAccessControlTests(TestCase):
    @unittest.mock.patch("django.conf.settings")
    def setUp(self, mock_settings: Any) -> None:
        # Configure settings
        mock_settings.configure_mock(
            ROOT_URLCONF=__name__,
            REST_FRAMEWORK={
                "DEFAULT_PERMISSION_CLASSES": [
                    "rest_framework.permissions.AllowAny",
                ],
                "DEFAULT_AUTHENTICATION_CLASSES": [
                    "rest_framework.authentication.BasicAuthentication",
                ],
            },
        )
        # Ensure urlpatterns are globally available in this module's scope for ROOT_URLCONF
        globals()["urlpatterns"] = urlpatterns

    @unittest.mock.patch("sys.stdout", new_callable=io.StringIO)
    def test_json_output(self, mock_stdout: Any) -> None:
        call_command("inspect_access_control", output="json")
        output_str = mock_stdout.getvalue()

        snapshot_path = os.path.join(os.path.dirname(__file__), "snapshot.json")
        with open(snapshot_path, "r") as f:
            snapshot_data = f.read()

        data = json.loads(output_str)
        expected_data = json.loads(snapshot_data)

        self.assertTrue(
            compare_nested_structures(data, expected_data),
            f"JSON structures don't match:\nGot: {data}\nExpected: {expected_data}",
        )

    @override_settings(ROOT_URLCONF="non_existent_module_for_testing")
    def test_error_invalid_root_urlconf(self) -> None:
        with self.assertRaises(CommandError) as cm:
            call_command("inspect_access_control")
        # The error message might vary slightly depending on Django versions or how it's caught.
        # Checking for part of the module name and a common error phrase.
        self.assertTrue(
            "non_existent_module_for_testing" in str(cm.exception)
            or "cannot import name" in str(cm.exception)
            or "ModuleNotFoundError"
            in str(cm.exception)  # More generic for module import failures
        )
