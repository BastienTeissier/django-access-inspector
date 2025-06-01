"""
Comprehensive tests for ViewInspectorService.

Tests cover:
- View function inspection
- Permission and authentication extraction
- Error handling and edge cases
- Default classes logic
- View splitting functionality
- Various view types (function-based, class-based, API views)
"""

from typing import Any, List
from unittest.mock import patch

from django.test import TestCase, override_settings

from django_access_inspector.services.models import (
    DefaultClasses,
    ViewFunction,
    ViewInspectionResult,
)
from django_access_inspector.services.view_inspector import ViewInspectorService


class MockPermissionClass:
    """Mock permission class for testing."""

    __name__ = "MockPermission"


class MockAuthenticationClass:
    """Mock authentication class for testing."""

    __name__ = "MockAuthentication"


class MockViewFunction:
    """Mock view function for testing."""

    def __init__(self, name: str = "mock_view"):
        self.__name__ = name


class MockClassBasedView:
    """Mock class-based view for testing."""

    def __init__(
        self, permissions: List[Any] = None, authentications: List[Any] = None
    ):
        self.permission_classes = permissions or []
        self.authentication_classes = authentications or []


class MockAPIView:
    """Mock API view class for testing."""

    def __init__(
        self, permissions: List[Any] = None, authentications: List[Any] = None
    ):
        self.permission_classes = permissions or []
        self.authentication_classes = authentications or []


class MockViewWithViewClass:
    """Mock function-based view with view_class attribute (decorated API view)."""

    def __init__(
        self, permissions: List[Any] = None, authentications: List[Any] = None
    ):
        self.view_class = MockAPIView(permissions, authentications)
        self.__name__ = "decorated_api_view"


class MockViewWithCls:
    """Mock view with cls attribute (class-based view)."""

    def __init__(
        self, permissions: List[Any] = None, authentications: List[Any] = None
    ):
        self.cls = MockClassBasedView(permissions, authentications)
        self.__name__ = "class_based_view"


class MockViewWithInitkwargs:
    """Mock view with initkwargs attribute."""

    def __init__(
        self, permissions: List[Any] = None, authentications: List[Any] = None
    ):
        self.initkwargs = MockAPIView(permissions, authentications)
        self.__name__ = "initkwargs_view"


class MockModelAdminView:
    """Mock model admin view."""

    def __init__(self):
        self.model_admin = True
        self.__name__ = "admin_view"


class TestViewInspectorService(TestCase):
    """Test suite for ViewInspectorService."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.service = ViewInspectorService()

    def test_inspect_view_function_with_view_class(self) -> None:
        """Test inspecting function-based view with view_class attribute."""
        permission = MockPermissionClass()
        authentication = MockAuthenticationClass()

        view_func = MockViewWithViewClass([permission], [authentication])
        view_function = ViewFunction(
            callback=view_func, pattern="api/test/", name="test_view"
        )

        result = self.service.inspect_view_function(view_function)

        self.assertEqual(result.url_name, "test_view")
        self.assertEqual(result.permission_classes, ["MockPermission"])
        self.assertEqual(result.authentication_classes, ["MockAuthentication"])

    def test_inspect_view_function_with_cls(self) -> None:
        """Test inspecting class-based view with cls attribute."""
        permission = MockPermissionClass()
        authentication = MockAuthenticationClass()

        view_func = MockViewWithCls([permission], [authentication])
        view_function = ViewFunction(
            callback=view_func, pattern="api/class/", name="class_view"
        )

        result = self.service.inspect_view_function(view_function)

        self.assertEqual(result.url_name, "class_view")
        self.assertEqual(result.permission_classes, ["MockPermission"])
        self.assertEqual(result.authentication_classes, ["MockAuthentication"])

    def test_inspect_view_function_with_initkwargs(self) -> None:
        """Test inspecting view with initkwargs attribute."""
        permission = MockPermissionClass()
        authentication = MockAuthenticationClass()

        view_func = MockViewWithInitkwargs([permission], [authentication])
        view_function = ViewFunction(
            callback=view_func, pattern="api/initkwargs/", name="initkwargs_view"
        )

        result = self.service.inspect_view_function(view_function)

        self.assertEqual(result.url_name, "initkwargs_view")
        self.assertEqual(result.permission_classes, ["MockPermission"])
        self.assertEqual(result.authentication_classes, ["MockAuthentication"])

    def test_inspect_view_function_model_admin(self) -> None:
        """Test inspecting model admin view."""
        view_func = MockModelAdminView()
        view_function = ViewFunction(
            callback=view_func, pattern="admin/", name="admin_view"
        )

        with self.assertRaises(ValueError) as cm:
            self.service.inspect_view_function(view_function)

        self.assertEqual(str(cm.exception), "model_admin")

    def test_inspect_view_function_unknown_type(self) -> None:
        """Test inspecting unknown view function type."""
        view_func = MockViewFunction("unknown_view")
        view_function = ViewFunction(
            callback=view_func, pattern="api/unknown/", name="unknown_view"
        )

        with self.assertRaises(ValueError) as cm:
            self.service.inspect_view_function(view_function)

        error_msg = str(cm.exception)
        self.assertTrue(error_msg.startswith("unknown:"))
        self.assertIn("unknown_view", error_msg)

    def test_inspect_view_function_no_name_attribute(self) -> None:
        """Test inspecting view function without __name__ attribute."""

        class ViewWithoutName:
            pass

        view_func = ViewWithoutName()
        view_function = ViewFunction(
            callback=view_func, pattern="api/no_name/", name="no_name_view"
        )

        with self.assertRaises(ValueError) as cm:
            self.service.inspect_view_function(view_function)

        error_msg = str(cm.exception)
        self.assertTrue(error_msg.startswith("unknown:"))
        self.assertIn("ViewWithoutName()", error_msg)

    def test_inspect_view_function_complex_object_repr(self) -> None:
        """Test inspecting view with complex object representation."""

        class ComplexView:
            def __repr__(self):
                return "<ComplexView object at 0x123456789>"

        view_func = ComplexView()
        view_function = ViewFunction(
            callback=view_func, pattern="api/complex/", name="complex_view"
        )

        with self.assertRaises(ValueError) as cm:
            self.service.inspect_view_function(view_function)

        error_msg = str(cm.exception)
        self.assertTrue(error_msg.startswith("unknown:"))
        # Should remove memory address from repr
        self.assertNotIn("0x123456789", error_msg)
        self.assertIn("ComplexView", error_msg)

    def test_inspect_view_function_empty_classes(self) -> None:
        """Test inspecting view with empty permission/authentication classes."""
        view_func = MockViewWithViewClass([], [])
        view_function = ViewFunction(
            callback=view_func, pattern="api/empty/", name="empty_view"
        )

        result = self.service.inspect_view_function(view_function)

        self.assertEqual(result.url_name, "empty_view")
        self.assertEqual(result.permission_classes, [])
        self.assertEqual(result.authentication_classes, [])

    def test_inspect_view_function_multiple_classes(self) -> None:
        """Test inspecting view with multiple permission/authentication classes."""
        permissions = [MockPermissionClass(), MockPermissionClass()]
        permissions[1].__name__ = "SecondPermission"

        authentications = [MockAuthenticationClass(), MockAuthenticationClass()]
        authentications[1].__name__ = "SecondAuthentication"

        view_func = MockViewWithViewClass(permissions, authentications)
        view_function = ViewFunction(
            callback=view_func, pattern="api/multiple/", name="multiple_view"
        )

        result = self.service.inspect_view_function(view_function)

        self.assertEqual(result.url_name, "multiple_view")
        self.assertEqual(len(result.permission_classes), 2)
        self.assertIn("MockPermission", result.permission_classes)
        self.assertIn("SecondPermission", result.permission_classes)
        self.assertEqual(len(result.authentication_classes), 2)
        self.assertIn("MockAuthentication", result.authentication_classes)
        self.assertIn("SecondAuthentication", result.authentication_classes)

    def test_inspect_view_function_duplicate_classes(self) -> None:
        """Test inspecting view with duplicate classes (should be deduplicated)."""
        permission = MockPermissionClass()
        authentication = MockAuthenticationClass()

        # Add the same classes multiple times
        view_func = MockViewWithViewClass(
            [permission, permission], [authentication, authentication]
        )
        view_function = ViewFunction(
            callback=view_func, pattern="api/duplicate/", name="duplicate_view"
        )

        result = self.service.inspect_view_function(view_function)

        # Should deduplicate classes
        self.assertEqual(len(result.permission_classes), 1)
        self.assertEqual(len(result.authentication_classes), 1)
        self.assertEqual(result.permission_classes, ["MockPermission"])
        self.assertEqual(result.authentication_classes, ["MockAuthentication"])

    def test_inspect_view_function_missing_attributes(self) -> None:
        """Test inspecting view with missing permission/authentication attributes."""

        class ViewWithoutAttributes:
            pass

        view_func = MockViewWithViewClass()
        view_func.view_class = ViewWithoutAttributes()

        view_function = ViewFunction(
            callback=view_func, pattern="api/missing/", name="missing_view"
        )

        result = self.service.inspect_view_function(view_function)

        self.assertEqual(result.permission_classes, [])
        self.assertEqual(result.authentication_classes, [])

    def test_inspect_view_function_unknown_class_name(self) -> None:
        """Test inspecting view with classes without __name__ attribute."""

        class ClassWithoutName:
            pass

        permission = ClassWithoutName()
        authentication = ClassWithoutName()

        view_func = MockViewWithViewClass([permission], [authentication])
        view_function = ViewFunction(
            callback=view_func, pattern="api/no_class_name/", name="no_class_name_view"
        )

        result = self.service.inspect_view_function(view_function)

        # Should use "unknown" for classes without __name__
        self.assertEqual(result.permission_classes, ["unknown"])
        self.assertEqual(result.authentication_classes, ["unknown"])

    def test_inspect_view_functions_mixed_results(self) -> None:
        """Test inspecting multiple view functions with mixed results."""
        # Valid view
        valid_view = ViewFunction(
            callback=MockViewWithViewClass(
                [MockPermissionClass()], [MockAuthenticationClass()]
            ),
            pattern="api/valid/",
            name="valid_view",
        )

        # Admin view
        admin_view = ViewFunction(
            callback=MockModelAdminView(),
            pattern="admin/model/",
            name="admin_model_view",
        )

        # Unknown view
        unknown_view = ViewFunction(
            callback=MockViewFunction(), pattern="api/unknown/", name="unknown_view"
        )

        view_functions = [valid_view, admin_view, unknown_view]

        result = self.service.inspect_view_functions(view_functions)

        # Check views
        self.assertEqual(len(result.views), 1)
        self.assertIn("valid_view", result.views)
        self.assertEqual(
            result.views["valid_view"].permission_classes, ["MockPermission"]
        )

        # Check admin views
        self.assertEqual(len(result.admin_views), 1)
        self.assertIn("admin_model_view", result.admin_views)

        # Check unchecked views
        self.assertEqual(len(result.unchecked_views), 1)
        self.assertEqual(result.unchecked_views[0].cause, "unknown")

    def test_inspect_view_functions_exception_handling(self) -> None:
        """Test handling of unexpected exceptions during view inspection."""

        class FailingView:
            @property
            def view_class(self):
                raise RuntimeError("Unexpected error")

        failing_view = ViewFunction(
            callback=FailingView(), pattern="api/failing/", name="failing_view"
        )

        result = self.service.inspect_view_functions([failing_view])

        # Should handle the exception and add to unchecked views
        self.assertEqual(len(result.views), 0)
        self.assertEqual(len(result.admin_views), 0)
        self.assertEqual(len(result.unchecked_views), 1)
        self.assertIn("Unexpected error", result.unchecked_views[0].cause)

    def test_inspect_view_functions_view_without_name(self) -> None:
        """Test inspecting view function where callback has no __name__."""

        class ViewWithoutName:
            pass

        view_without_name = ViewFunction(
            callback=ViewWithoutName(), pattern="api/no_name/", name="no_name_view"
        )

        with patch("django_access_inspector.services.view_inspector.logger"):
            result = self.service.inspect_view_functions([view_without_name])

        self.assertEqual(len(result.unchecked_views), 1)
        self.assertIn("no_name_view / ViewWithoutName", result.unchecked_views[0].view)

    def test_inspect_view_functions_none_url_name(self) -> None:
        """Test inspecting view functions with None as url_name."""
        view_with_none_name = ViewFunction(
            callback=MockViewWithViewClass([MockPermissionClass()], []),
            pattern="api/none_name/",
            name=None,
        )

        result = self.service.inspect_view_functions([view_with_none_name])

        # Should not add views with None names to the results
        self.assertEqual(len(result.views), 0)

    @override_settings()
    def test_get_default_classes_no_rest_framework(self) -> None:
        """Test getting default classes when REST_FRAMEWORK is not configured."""
        # Remove REST_FRAMEWORK setting if it exists
        from django.conf import settings

        if hasattr(settings, "REST_FRAMEWORK"):
            delattr(settings, "REST_FRAMEWORK")

        result = self.service.get_default_classes()

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
        result = self.service.get_default_classes()

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
        result = self.service.get_default_classes()

        self.assertEqual(result.permission, [])
        self.assertEqual(result.authentication, [])

    @override_settings(REST_FRAMEWORK={})
    def test_get_default_classes_rest_framework_no_defaults(self) -> None:
        """Test getting default classes with REST_FRAMEWORK but no default classes defined."""
        result = self.service.get_default_classes()

        self.assertEqual(result.permission, [])
        self.assertEqual(result.authentication, [])

    @override_settings(
        REST_FRAMEWORK={
            "DEFAULT_PERMISSION_CLASSES": ["app.permissions.CustomPermission"],
            # Missing DEFAULT_AUTHENTICATION_CLASSES
        }
    )
    def test_get_default_classes_partial_rest_framework(self) -> None:
        """Test getting default classes with partial REST_FRAMEWORK configuration."""
        result = self.service.get_default_classes()

        self.assertEqual(result.permission, ["CustomPermission"])
        self.assertEqual(result.authentication, [])  # Should default to empty list

    def test_split_views_by_authentication_basic(self) -> None:
        """Test basic view splitting by authentication."""
        views = {
            "authenticated_view": ViewInspectionResult(
                url_name="authenticated_view",
                permission_classes=["IsAuthenticated"],
                authentication_classes=["TokenAuthentication"],
            ),
            "permission_only_view": ViewInspectionResult(
                url_name="permission_only_view",
                permission_classes=["IsAuthenticated"],
                authentication_classes=[],
            ),
            "unauthenticated_view": ViewInspectionResult(
                url_name="unauthenticated_view",
                permission_classes=[],
                authentication_classes=[],
            ),
        }

        result = self.service.split_views_by_authentication(views)

        # Views with either permission or authentication classes should be in authenticated
        self.assertEqual(len(result.authenticated), 2)
        self.assertIn("authenticated_view", result.authenticated)
        self.assertIn("permission_only_view", result.authenticated)

        # Views with no classes should be in unauthenticated
        self.assertEqual(len(result.unauthenticated), 1)
        self.assertIn("unauthenticated_view", result.unauthenticated)

    def test_split_views_by_authentication_edge_cases(self) -> None:
        """Test view splitting with edge cases."""
        views = {
            "auth_only_view": ViewInspectionResult(
                url_name="auth_only_view",
                permission_classes=[],
                authentication_classes=["TokenAuthentication"],
            ),
            "empty_view": ViewInspectionResult(
                url_name="empty_view",
                permission_classes=[],
                authentication_classes=[],
            ),
        }

        result = self.service.split_views_by_authentication(views)

        # View with only authentication classes should be in authenticated
        self.assertEqual(len(result.authenticated), 1)
        self.assertIn("auth_only_view", result.authenticated)

        # View with no classes should be in unauthenticated
        self.assertEqual(len(result.unauthenticated), 1)
        self.assertIn("empty_view", result.unauthenticated)

    def test_split_views_by_authentication_empty_dict(self) -> None:
        """Test view splitting with empty views dictionary."""
        result = self.service.split_views_by_authentication({})

        self.assertEqual(len(result.authenticated), 0)
        self.assertEqual(len(result.unauthenticated), 0)

    def test_split_views_by_authentication_all_authenticated(self) -> None:
        """Test view splitting where all views are authenticated."""
        views = {
            "view1": ViewInspectionResult(
                url_name="view1",
                permission_classes=["IsAuthenticated"],
                authentication_classes=[],
            ),
            "view2": ViewInspectionResult(
                url_name="view2",
                permission_classes=[],
                authentication_classes=["TokenAuthentication"],
            ),
        }

        result = self.service.split_views_by_authentication(views)

        self.assertEqual(len(result.authenticated), 2)
        self.assertEqual(len(result.unauthenticated), 0)

    def test_split_views_by_authentication_all_unauthenticated(self) -> None:
        """Test view splitting where all views are unauthenticated."""
        views = {
            "view1": ViewInspectionResult(
                url_name="view1",
                permission_classes=[],
                authentication_classes=[],
            ),
            "view2": ViewInspectionResult(
                url_name="view2",
                permission_classes=[],
                authentication_classes=[],
            ),
        }

        result = self.service.split_views_by_authentication(views)

        self.assertEqual(len(result.authenticated), 0)
        self.assertEqual(len(result.unauthenticated), 2)

    def test_integration_full_analysis_workflow(self) -> None:
        """Test the complete analysis workflow integration."""
        # Create a comprehensive set of view functions
        view_functions = [
            # Valid authenticated view
            ViewFunction(
                callback=MockViewWithViewClass(
                    [MockPermissionClass()], [MockAuthenticationClass()]
                ),
                pattern="api/auth/",
                name="auth_view",
            ),
            # Valid unauthenticated view
            ViewFunction(
                callback=MockViewWithCls([], []),
                pattern="api/public/",
                name="public_view",
            ),
            # Admin view
            ViewFunction(
                callback=MockModelAdminView(),
                pattern="admin/users/",
                name="admin_users",
            ),
            # Unknown view
            ViewFunction(
                callback=MockViewFunction("unknown"),
                pattern="api/unknown/",
                name="unknown_view",
            ),
        ]

        # Run full analysis
        analysis_result = self.service.inspect_view_functions(view_functions)

        # Verify analysis results
        self.assertEqual(len(analysis_result.views), 2)
        self.assertEqual(len(analysis_result.admin_views), 1)
        self.assertEqual(len(analysis_result.unchecked_views), 1)

        # Test view splitting
        split_views = self.service.split_views_by_authentication(analysis_result.views)

        self.assertEqual(len(split_views.authenticated), 1)  # auth_view
        self.assertEqual(len(split_views.unauthenticated), 1)  # public_view

        # Test default classes
        default_classes = self.service.get_default_classes()
        self.assertIsInstance(default_classes, DefaultClasses)
        self.assertIsInstance(default_classes.authentication, list)
        self.assertIsInstance(default_classes.permission, list)
