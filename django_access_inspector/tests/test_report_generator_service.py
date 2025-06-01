"""
Comprehensive tests for ReportGeneratorService.

Tests cover:
- JSON report generation
- Terminal report formatting
- Statistics calculations
- Settings integration
- Edge cases and error handling
"""

import json
from io import StringIO
from unittest.mock import patch

from django.test import TestCase, override_settings

from django_access_inspector.services.models import (
    DefaultClasses,
    SplitViews,
    UncheckedView,
    ViewInspectionResult,
)
from django_access_inspector.services.report_generator import ReportGeneratorService


class TestReportGeneratorService(TestCase):
    """Test suite for ReportGeneratorService."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.service = ReportGeneratorService()

        # Sample test data
        self.sample_views = {
            "api/users/": ViewInspectionResult(
                url_name="api/users/",
                permission_classes=["IsAuthenticated"],
                authentication_classes=["TokenAuthentication"],
            ),
            "api/public/": ViewInspectionResult(
                url_name="api/public/",
                permission_classes=[],
                authentication_classes=[],
            ),
            "api/admin/": ViewInspectionResult(
                url_name="api/admin/",
                permission_classes=["IsAuthenticated", "IsAdminUser"],
                authentication_classes=["SessionAuthentication"],
            ),
        }

        self.sample_unchecked_views = [
            UncheckedView(view="unknown_view", cause="unknown"),
            UncheckedView(view="error_view", cause="import_error"),
        ]

        self.sample_admin_views = ["admin:index", "admin:user_changelist"]

        self.sample_split_views = SplitViews(
            authenticated={
                "api/users/": ViewInspectionResult(
                    url_name="api/users/",
                    permission_classes=["IsAuthenticated"],
                    authentication_classes=["TokenAuthentication"],
                ),
            },
            unauthenticated={
                "api/public/": ViewInspectionResult(
                    url_name="api/public/",
                    permission_classes=[],
                    authentication_classes=[],
                ),
            },
        )

    def test_generate_json_report_from_split_views(self) -> None:
        """Test JSON report generation from SplitViews."""
        result = self.service.generate_json_report_from_split_views(
            self.sample_split_views,
            self.sample_admin_views,
            self.sample_unchecked_views,
        )

        # Parse the JSON to verify structure
        data = json.loads(result)

        # Verify main structure
        self.assertIn("views", data)
        self.assertIn("model_admin_views", data)
        self.assertIn("unchecked_views", data)

        # Verify views structure
        views = data["views"]
        self.assertIn("authenticated", views)
        self.assertIn("unauthenticated", views)

        # Verify authenticated views
        auth_views = views["authenticated"]
        self.assertIn("api/users/", auth_views)
        self.assertEqual(
            auth_views["api/users/"]["permission_classes"], ["IsAuthenticated"]
        )
        self.assertEqual(
            auth_views["api/users/"]["authentication_classes"], ["TokenAuthentication"]
        )

        # Verify unauthenticated views
        unauth_views = views["unauthenticated"]
        self.assertIn("api/public/", unauth_views)
        self.assertEqual(unauth_views["api/public/"]["permission_classes"], [])
        self.assertEqual(unauth_views["api/public/"]["authentication_classes"], [])

        # Verify admin views
        self.assertEqual(data["model_admin_views"], self.sample_admin_views)

        # Verify unchecked views
        unchecked = data["unchecked_views"]
        self.assertEqual(len(unchecked), 2)
        self.assertEqual(unchecked[0]["view"], "unknown_view")
        self.assertEqual(unchecked[0]["cause"], "unknown")

    def test_convert_split_views_to_json(self) -> None:
        """Test conversion of SplitViews to JSON format."""
        result = self.service._convert_split_views_to_json(self.sample_split_views)

        # Verify structure
        self.assertIn("authenticated", result)
        self.assertIn("unauthenticated", result)

        # Verify authenticated section
        auth = result["authenticated"]
        self.assertIn("api/users/", auth)
        self.assertEqual(auth["api/users/"]["permission_classes"], ["IsAuthenticated"])

        # Verify unauthenticated section
        unauth = result["unauthenticated"]
        self.assertIn("api/public/", unauth)
        self.assertEqual(unauth["api/public/"]["permission_classes"], [])

    @patch("sys.stdout", new_callable=StringIO)
    def test_print_terminal_report(self, mock_stdout: StringIO) -> None:
        """Test terminal report printing functionality."""
        # Use a real console but capture output
        with patch.object(self.service, "console") as mock_console:
            self.service.print_terminal_report(
                self.sample_views,
                self.sample_unchecked_views,
                self.sample_admin_views,
            )

            # Verify that console.print was called multiple times
            self.assertGreater(mock_console.print.call_count, 3)

    def test_print_unchecked_views_table(self) -> None:
        """Test unchecked views table formatting."""
        with patch.object(self.service, "console") as mock_console:
            self.service._print_unchecked_views_table(self.sample_unchecked_views)

            # Verify console.print was called with a table
            mock_console.print.assert_called_once()
            args = mock_console.print.call_args[0]
            # The argument should be a Rich Table
            self.assertTrue(hasattr(args[0], "add_row"))

    def test_print_unchecked_views_table_empty(self) -> None:
        """Test unchecked views table with empty list."""
        with patch.object(self.service, "console") as mock_console:
            self.service._print_unchecked_views_table([])

            # Should still print the table, even if empty
            mock_console.print.assert_called_once()

    def test_print_admin_views_table(self) -> None:
        """Test admin views table formatting."""
        with patch.object(self.service, "console") as mock_console:
            self.service._print_admin_views_table(self.sample_admin_views)

            mock_console.print.assert_called_once()
            args = mock_console.print.call_args[0]
            self.assertTrue(hasattr(args[0], "add_row"))

    def test_print_admin_views_table_with_none_values(self) -> None:
        """Test admin views table with None values."""
        admin_views_with_none = ["admin:index", None, "admin:user_changelist"]

        with patch.object(self.service, "console") as mock_console:
            self.service._print_admin_views_table(admin_views_with_none)

            # Should still work and filter out None values
            mock_console.print.assert_called_once()

    def test_print_main_views_table(self) -> None:
        """Test main views table formatting."""
        default_classes = DefaultClasses(
            authentication=["BasicAuthentication"], permission=["AllowAny"]
        )

        with patch.object(self.service, "console") as mock_console:
            self.service._print_main_views_table(self.sample_views, default_classes)

            mock_console.print.assert_called_once()
            args = mock_console.print.call_args[0]
            self.assertTrue(hasattr(args[0], "add_row"))

    def test_print_main_views_table_with_none_url(self) -> None:
        """Test main views table with None URL values."""
        views_with_none = {
            None: ViewInspectionResult(
                url_name=None,
                permission_classes=["IsAuthenticated"],
                authentication_classes=["TokenAuthentication"],
            ),
            "api/valid/": self.sample_views["api/users/"],
        }

        default_classes = DefaultClasses(
            authentication=["BasicAuthentication"], permission=["AllowAny"]
        )

        with patch.object(self.service, "console") as mock_console:
            self.service._print_main_views_table(views_with_none, default_classes)

            # Should filter out None URLs
            mock_console.print.assert_called_once()

    def test_print_summary_panels(self) -> None:
        """Test summary panels printing."""
        default_classes = DefaultClasses(
            authentication=["BasicAuthentication"], permission=["AllowAny"]
        )

        with patch.object(self.service, "console") as mock_console:
            self.service._print_summary_panels(
                self.sample_views,
                self.sample_unchecked_views,
                self.sample_admin_views,
                default_classes,
            )

            # Should print 3 panels: Details, Authentication, Permission
            self.assertEqual(mock_console.print.call_count, 3)

    def test_render_class_cell_empty(self) -> None:
        """Test rendering cell with no classes."""
        result = self.service._render_class_cell([], ["AllowAny"])

        self.assertEqual(result.plain, "None")
        self.assertEqual(result.style, "bold red")

    def test_render_class_cell_default(self) -> None:
        """Test rendering cell with default classes."""
        result = self.service._render_class_cell(["AllowAny"], ["AllowAny"])

        self.assertEqual(result.plain, "AllowAny")
        self.assertEqual(result.style, "bold yellow")

    def test_render_class_cell_custom(self) -> None:
        """Test rendering cell with custom classes."""
        result = self.service._render_class_cell(
            ["IsAuthenticated", "IsAdminUser"], ["AllowAny"]
        )

        self.assertEqual(result.plain, "IsAuthenticated, IsAdminUser")
        # No special styling for custom classes (returns Text with no style)
        self.assertEqual(result.style, "")

    def test_render_class_cell_single_custom(self) -> None:
        """Test rendering cell with single custom class."""
        result = self.service._render_class_cell(["IsAuthenticated"], ["AllowAny"])

        self.assertEqual(result.plain, "IsAuthenticated")
        self.assertEqual(result.style, "")

    def test_count_ko_and_default(self) -> None:
        """Test counting views with no classes and default classes."""
        classes_list = [
            [],  # No classes
            ["AllowAny"],  # Default class
            ["IsAuthenticated"],  # Custom class
            [],  # No classes
            ["AllowAny"],  # Default class
            ["IsAuthenticated", "IsAdminUser"],  # Multiple custom classes
        ]

        no_classes, default_classes = self.service._count_ko_and_default(
            classes_list, ["AllowAny"]
        )

        self.assertEqual(no_classes, 2)
        self.assertEqual(default_classes, 2)

    def test_count_ko_and_default_empty_list(self) -> None:
        """Test counting with empty classes list."""
        no_classes, default_classes = self.service._count_ko_and_default(
            [], ["AllowAny"]
        )

        self.assertEqual(no_classes, 0)
        self.assertEqual(default_classes, 0)

    def test_set_color_zero(self) -> None:
        """Test color setting for zero count."""
        color = self.service._set_color(0)
        self.assertEqual(color, "green")

    def test_set_color_positive(self) -> None:
        """Test color setting for positive count."""
        color = self.service._set_color(5)
        self.assertEqual(color, "red")

    def test_set_color_negative(self) -> None:
        """Test color setting for negative count."""
        color = self.service._set_color(-1)
        self.assertEqual(color, "red")

    @override_settings()
    def test_get_default_classes_no_rest_framework(self) -> None:
        """Test getting default classes when REST_FRAMEWORK is not configured."""
        # Remove REST_FRAMEWORK setting if it exists
        from django.conf import settings

        if hasattr(settings, "REST_FRAMEWORK"):
            delattr(settings, "REST_FRAMEWORK")

        result = self.service._get_default_classes()

        self.assertEqual(result.authentication, ["BasicAuthentication"])
        self.assertEqual(result.permission, ["AllowAny"])

    @override_settings(
        REST_FRAMEWORK={
            "DEFAULT_PERMISSION_CLASSES": [
                "rest_framework.permissions.IsAuthenticated",
                "myapp.permissions.CustomPermission",
            ],
            "DEFAULT_AUTHENTICATION_CLASSES": [
                "rest_framework.authentication.TokenAuthentication",
                "rest_framework.authentication.SessionAuthentication",
            ],
        }
    )
    def test_get_default_classes_with_rest_framework(self) -> None:
        """Test getting default classes with REST_FRAMEWORK configured."""
        result = self.service._get_default_classes()

        self.assertEqual(result.permission, ["IsAuthenticated", "CustomPermission"])
        self.assertEqual(
            result.authentication, ["TokenAuthentication", "SessionAuthentication"]
        )

    @override_settings(
        REST_FRAMEWORK={
            "DEFAULT_PERMISSION_CLASSES": [],
            "DEFAULT_AUTHENTICATION_CLASSES": [],
        }
    )
    def test_get_default_classes_empty_rest_framework(self) -> None:
        """Test getting default classes with empty REST_FRAMEWORK lists."""
        result = self.service._get_default_classes()

        self.assertEqual(result.permission, [])
        self.assertEqual(result.authentication, [])

    @override_settings(REST_FRAMEWORK={})
    def test_get_default_classes_rest_framework_no_defaults(self) -> None:
        """Test getting default classes with REST_FRAMEWORK but no default classes defined."""
        result = self.service._get_default_classes()

        self.assertEqual(result.permission, [])
        self.assertEqual(result.authentication, [])

    def test_json_report_complex_data(self) -> None:
        """Test JSON report generation with complex nested data."""
        complex_split_views = SplitViews(
            authenticated={
                "api/users/": ViewInspectionResult(
                    url_name="api/users/",
                    permission_classes=["IsAuthenticated", "IsOwnerOrReadOnly"],
                    authentication_classes=[
                        "TokenAuthentication",
                        "SessionAuthentication",
                    ],
                ),
                "api/admin/deep/nested/": ViewInspectionResult(
                    url_name="api/admin/deep/nested/",
                    permission_classes=[
                        "IsAuthenticated",
                        "IsAdminUser",
                        "CustomPermission",
                    ],
                    authentication_classes=["TokenAuthentication"],
                ),
            },
            unauthenticated={
                "api/public/health/": ViewInspectionResult(
                    url_name="api/public/health/",
                    permission_classes=[],
                    authentication_classes=[],
                ),
            },
        )

        complex_unchecked = [
            UncheckedView(view="complex.view.path", cause="import_error"),
            UncheckedView(view="another.complex.view", cause="unknown"),
        ]

        complex_admin = ["admin:complex_model_changelist", "admin:another_model_add"]

        result = self.service.generate_json_report_from_split_views(
            complex_split_views,
            complex_admin,
            complex_unchecked,
        )

        # Parse and verify the complex structure
        data = json.loads(result)

        # Verify complex authenticated view
        auth_view = data["views"]["authenticated"]["api/admin/deep/nested/"]
        self.assertEqual(len(auth_view["permission_classes"]), 3)
        self.assertIn("IsAdminUser", auth_view["permission_classes"])

        # Verify the JSON is valid and complete
        self.assertIsInstance(data, dict)
        self.assertEqual(len(data["unchecked_views"]), 2)
        self.assertEqual(len(data["model_admin_views"]), 2)

    def test_edge_case_empty_data(self) -> None:
        """Test handling of completely empty data."""
        empty_split_views = SplitViews(authenticated={}, unauthenticated={})

        result = self.service.generate_json_report_from_split_views(
            empty_split_views, [], []
        )

        data = json.loads(result)

        self.assertEqual(data["views"]["authenticated"], {})
        self.assertEqual(data["views"]["unauthenticated"], {})
        self.assertEqual(data["model_admin_views"], [])
        self.assertEqual(data["unchecked_views"], [])

    def test_statistics_edge_cases(self) -> None:
        """Test statistics calculations with edge case data."""
        # Test with all views having empty classes
        empty_views = {
            "view1": ViewInspectionResult("view1", [], []),
            "view2": ViewInspectionResult("view2", [], []),
        }

        default_classes = DefaultClasses(
            authentication=["BasicAuthentication"], permission=["AllowAny"]
        )

        with patch.object(self.service, "console"):
            # Should not raise any exceptions
            self.service._print_summary_panels(empty_views, [], [], default_classes)

        # Test counting with all empty
        no_classes, default_classes_count = self.service._count_ko_and_default(
            [[], []], ["AllowAny"]
        )
        self.assertEqual(no_classes, 2)
        self.assertEqual(default_classes_count, 0)
