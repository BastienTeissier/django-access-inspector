from io import StringIO
import json

from django.urls import path
from django.core.management import call_command
from django.test import TestCase
from django.test.utils import override_settings

from unittest.mock import patch

from django_access_inspector.tests.mocks.views import (
    DemoAttribute,
    DemoDecorator,
    NoAuthDemo,
    example_view,
)


urlpatterns = [
    path(
        "decorator/",
        DemoDecorator.as_view(),
        name="decorator",
    ),
    path("function", example_view, name="function"),
    path(
        "attribute/",
        DemoAttribute.as_view(),
        name="attribute",
    ),
    path(
        "no-auth/",
        NoAuthDemo.as_view(),
        name="no-auth",
    ),
]


@override_settings(
    ROOT_URLCONF="django_access_inspector.tests.management.command.test_inspect_access_control"
)
class ShowUrlsTests(TestCase):
    @patch("sys.stdout", new_callable=StringIO)
    def test_output_views_scan_access(self, m_stdout):
        call_command("inspect_access_control")

        views = json.loads(m_stdout.getvalue())["views"]
        assert len(views["authenticated"]) == 4
        assert len(views["unauthenticated"]) == 0
