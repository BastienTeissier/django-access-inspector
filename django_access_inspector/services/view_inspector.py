"""
View Inspector Service for Django Access Inspector.

This service handles the inspection of view functions to extract permission
and authentication class information.
"""

import inspect
import logging
import re
from typing import Any, Dict, List

from django.conf import settings

from .debug_logger import get_debug_logger
from .models import (
    AnalysisResult,
    DefaultClasses,
    SplitViews,
    UncheckedView,
    ViewFunction,
    ViewInspectionResult,
)

logger = logging.getLogger(__name__)


class ViewInspectorService:
    """Service responsible for inspecting views for permissions and authentication."""

    def inspect_view_function(self, view_func: ViewFunction) -> ViewInspectionResult:
        """
        Inspect a single view function to extract permission and authentication classes.

        Returns ViewInspectionResult with extracted classes, or raises exception for unchecked views.
        """
        debug_logger = get_debug_logger()
        func, pattern, url_name = view_func.callback, view_func.pattern, view_func.name

        debug_logger.log_view_inspection_start(func, pattern, url_name)

        permissions = []
        authentications = []
        detection_path = "unknown"

        # Check for model admin views
        if hasattr(func, "model_admin"):
            debug_logger.log_admin_view_detection(url_name, "model_admin attribute")
            raise ValueError("model_admin")

        # Analyze Django-native authentication patterns
        django_auth = self._analyze_django_authentication(func)
        source_hints = self._get_view_source_hints(func)
        debug_logger.log_django_auth_analysis(
            func,
            django_auth["decorators"],
            django_auth["mixins"],
            django_auth["middleware_hints"],
        )

        # Check for view_class attribute - could be DRF @api_view or Django CBV
        if hasattr(func, "view_class"):
            # Determine if this is a Django CBV or DRF view
            if self._is_django_cbv(func):
                detection_path = "Django class-based view"
                # For Django CBVs, we rely on the Django auth analysis above
                # Add Django authentication detection to permissions/authentications
                if django_auth["decorators"]:
                    authentications.extend(
                        [
                            f"Django:{decorator}"
                            for decorator in django_auth["decorators"]
                        ]
                    )
                if django_auth["mixins"]:
                    authentications.extend(
                        [f"Django:{mixin}" for mixin in django_auth["mixins"]]
                    )
                if django_auth["middleware_hints"]:
                    authentications.extend(
                        [f"Django:{hint}" for hint in django_auth["middleware_hints"]]
                    )
                if source_hints:
                    authentications.extend(
                        [f"SourceHint:{hint}" for hint in source_hints]
                    )
            else:
                # This is a DRF @api_view decorated function
                detection_path = "DRF @api_view decorator"
                permission_classes = getattr(func.view_class, "permission_classes", [])
                permissions.extend(
                    [
                        permission_class                             # keep string as-is
                        if isinstance(permission_class, str)
                        else getattr(permission_class, "__name__", "unknown")
                        for permission_class in permission_classes
                    ]
                )
                authentications.extend(
                    [
                        getattr(authentication_class, "__name__", "unknown")
                        for authentication_class in getattr(
                            func.view_class, "authentication_classes", []
                        )
                    ]
                )
        # Check for cls attribute (class-based views)
        elif hasattr(func, "cls"):
            detection_path = "DRF class-based view"
            permissions.extend(
                [
                    getattr(permission_class, "__name__", "unknown")
                    for permission_class in getattr(func.cls, "permission_classes", [])
                ]
            )
            authentications.extend(
                [
                    getattr(authentication_class, "__name__", "unknown")
                    for authentication_class in getattr(
                        func.cls, "authentication_classes", []
                    )
                ]
            )
        # Check for initkwargs attribute
        elif hasattr(func, "initkwargs"):
            detection_path = "view with initkwargs"
            permissions.extend(
                [
                    getattr(permission_class, "__name__", "unknown")
                    for permission_class in getattr(
                        func.initkwargs, "permission_classes", []
                    )
                ]
            )
            authentications.extend(
                [
                    getattr(authentication_class, "__name__", "unknown")
                    for authentication_class in getattr(
                        func.initkwargs, "authentication_classes", []
                    )
                ]
            )
        else:
            # Check if we have any Django authentication patterns
            has_django_patterns = (
                django_auth["decorators"]
                or django_auth["mixins"]
                or django_auth["middleware_hints"]
                or source_hints
            )

            if has_django_patterns:
                detection_path = "Django native patterns"
                # Add Django authentication detection to permissions/authentications
                if django_auth["decorators"]:
                    authentications.extend(
                        [
                            f"Django:{decorator}"
                            for decorator in django_auth["decorators"]
                        ]
                    )
                if django_auth["mixins"]:
                    authentications.extend(
                        [f"Django:{mixin}" for mixin in django_auth["mixins"]]
                    )
                if django_auth["middleware_hints"]:
                    authentications.extend(
                        [f"Django:{hint}" for hint in django_auth["middleware_hints"]]
                    )
                if source_hints:
                    authentications.extend(
                        [f"SourceHint:{hint}" for hint in source_hints]
                    )
            else:
                # No special attributes and no Django patterns - truly unknown
                detection_path = "unknown"

        # Log the detection results
        debug_logger.log_authentication_detection(
            func, detection_path, permissions, authentications
        )

        # If no authentication found through any method AND detection path is truly unknown, mark as unchecked
        # Views with a valid detection path (like "Django native patterns", "Django class-based view", etc.)
        # but empty classes are still valid - they are intentionally unauthenticated views
        if (
            not permissions
            and not authentications
            and detection_path == "unknown"
            and not django_auth["decorators"]
            and not django_auth["mixins"]
            and not django_auth["middleware_hints"]
            and not source_hints
        ):
            # Unknown function type - create descriptive name for unchecked view
            if hasattr(func, "__name__"):
                func_repr = func.__name__
            elif hasattr(func, "__class__"):
                func_repr = f"{getattr(func.__class__, '__name__', 'unknown')}()"
            else:
                func_repr = re.sub(r" at 0x[0-9a-f]+", "", repr(func))

            debug_logger.log_unchecked_view(
                f"{url_name} / {func_repr}", "No authentication patterns detected", True
            )
            raise ValueError(f"unknown:{url_name} / {func_repr}")

        result = ViewInspectionResult(
            url_name=url_name,
            permission_classes=list(set(permissions)),
            authentication_classes=list(set(authentications)),
        )

        # Log categorization decision
        if permissions or authentications:
            debug_logger.log_categorization_decision(
                url_name,
                "AUTHENTICATED",
                f"Found via {detection_path}",
                [f"Permissions: {permissions}", f"Authentications: {authentications}"],
            )

        return result

    def inspect_view_functions(
        self, view_functions: List[ViewFunction]
    ) -> AnalysisResult:
        """
        Inspect a list of view functions and return analysis results.

        Returns AnalysisResult containing views, admin_views, and unchecked_views.
        """
        views = {}
        unchecked_views = []
        admin_views = []

        for view_func in view_functions:
            try:
                result = self.inspect_view_function(view_func)
                if result.url_name is not None:
                    views[result.url_name] = result
            except ValueError as e:
                error_str = str(e)
                if error_str == "model_admin":
                    if view_func.name is not None:
                        admin_views.append(view_func.name)
                elif error_str.startswith("unknown:"):
                    view_info = error_str[8:]  # Remove "unknown:" prefix
                    unchecked_views.append(
                        UncheckedView(view=view_info, cause="unknown")
                    )
                else:
                    unchecked_views.append(
                        UncheckedView(
                            view=f"{view_func.name} / {getattr(view_func.callback, '__name__', 'unknown')}",
                            cause=error_str,
                        )
                    )
            except Exception as e:
                func_name = (
                    getattr(view_func.callback, "__name__", "unknown")
                    if hasattr(view_func.callback, "__name__")
                    else "unknown"
                )
                logger.exception(
                    f"Error processing view {view_func.name} / {func_name}: {e}"
                )
                unchecked_views.append(
                    UncheckedView(view=f"{view_func.name} / {func_name}", cause=str(e))
                )

        return AnalysisResult(
            views=views, admin_views=admin_views, unchecked_views=unchecked_views
        )

    def get_default_classes(self) -> DefaultClasses:
        """Get default authentication and permission classes from Django settings."""
        default_classes = DefaultClasses(
            authentication=["BasicAuthentication"], permission=["AllowAny"]
        )

        if getattr(settings, "REST_FRAMEWORK", None) is None:
            return default_classes

        default_classes.permission = [
            c.split(".")[-1]
            for c in settings.REST_FRAMEWORK.get("DEFAULT_PERMISSION_CLASSES", [])
        ]
        default_classes.authentication = [
            c.split(".")[-1]
            for c in settings.REST_FRAMEWORK.get("DEFAULT_AUTHENTICATION_CLASSES", [])
        ]

        return default_classes

    def split_views_by_authentication(
        self, views: Dict[str, ViewInspectionResult]
    ) -> SplitViews:
        """Split views into authenticated and unauthenticated categories."""
        debug_logger = get_debug_logger()
        authenticated = {}
        unauthenticated = {}

        for url, view_result in views.items():
            has_auth = len(view_result.authentication_classes) > 0
            has_perms = len(view_result.permission_classes) > 0

            if has_auth or has_perms:
                authenticated[url] = view_result
                debug_logger.log_categorization_decision(
                    url,
                    "AUTHENTICATED",
                    "Has authentication or permission classes",
                    [
                        f"Authentication classes: {view_result.authentication_classes}",
                        f"Permission classes: {view_result.permission_classes}",
                    ],
                )
            else:
                unauthenticated[url] = view_result
                debug_logger.log_categorization_decision(
                    url,
                    "UNAUTHENTICATED",
                    "No authentication or permission classes found",
                    [
                        f"Authentication classes: {view_result.authentication_classes}",
                        f"Permission classes: {view_result.permission_classes}",
                    ],
                )

        return SplitViews(authenticated=authenticated, unauthenticated=unauthenticated)

    def _analyze_django_authentication(self, func: Any) -> Dict[str, List[str]]:
        """
        Analyze Django-native authentication patterns on a view function.

        Returns dict with 'decorators', 'mixins', and 'middleware_hints' keys.
        """
        result = {
            "decorators": [],
            "mixins": [],
            "middleware_hints": [],
        }

        # Check for function decorators
        if hasattr(func, "__wrapped__"):
            # This indicates the function has been decorated
            current = func
            while hasattr(current, "__wrapped__"):
                if hasattr(current, "__name__"):
                    decorator_name = current.__name__
                    if "login_required" in decorator_name:
                        result["decorators"].append("login_required")
                    elif "permission_required" in decorator_name:
                        result["decorators"].append("permission_required")
                    elif "user_passes_test" in decorator_name:
                        result["decorators"].append("user_passes_test")
                current = current.__wrapped__

        # Check for decorator attributes that Django adds
        if hasattr(func, "__name__"):
            # Django login_required decorator adds attributes
            if hasattr(func, "login_url") or "login_required" in str(func):
                result["decorators"].append("login_required")

        # For class-based views, check for authentication mixins
        # Check both DRF-style cls and Django-style view_class
        view_class = None
        if hasattr(func, "cls"):
            view_class = func.cls
        elif hasattr(func, "view_class"):
            view_class = func.view_class

        if view_class:
            try:
                # Check if view_class is actually a class (not an instance)
                if inspect.isclass(view_class):
                    mro = inspect.getmro(view_class)
                    for base_class in mro:
                        class_name = base_class.__name__
                        if "LoginRequired" in class_name:
                            result["mixins"].append(class_name)
                        elif "PermissionRequired" in class_name:
                            result["mixins"].append(class_name)
                        elif "UserPassesTest" in class_name:
                            result["mixins"].append(class_name)
                else:
                    # It's an instance, check its class
                    view_class_type = type(view_class)
                    mro = inspect.getmro(view_class_type)
                    for base_class in mro:
                        class_name = base_class.__name__
                        if "LoginRequired" in class_name:
                            result["mixins"].append(class_name)
                        elif "PermissionRequired" in class_name:
                            result["mixins"].append(class_name)
                        elif "UserPassesTest" in class_name:
                            result["mixins"].append(class_name)
            except (TypeError, AttributeError):
                # Skip if we can't analyze the class hierarchy
                pass

        # Check for admin views
        if hasattr(func, "model_admin") or "admin" in str(func):
            result["middleware_hints"].append("admin_authentication")

        # Check for Django's built-in auth views
        if hasattr(func, "__module__"):
            module = func.__module__
            if "django.contrib.auth" in module:
                result["middleware_hints"].append("django_auth_views")
            elif "django.contrib.admin" in module:
                result["middleware_hints"].append("django_admin_views")

        return result

    def _get_view_source_hints(self, func: Any) -> List[str]:
        """
        Try to get hints about authentication from view source code.
        This is a fallback method for complex cases.
        """
        hints = []

        try:
            if hasattr(func, "cls"):
                # For class-based views, check the class source
                source = inspect.getsource(func.cls)
            elif callable(func):
                source = inspect.getsource(func)
            else:
                return hints

            # Look for common authentication patterns in source
            if "request.user.is_authenticated" in source:
                hints.append("manual_auth_check")
            if "login_required" in source:
                hints.append("login_required_mentioned")
            if "permission_required" in source:
                hints.append("permission_required_mentioned")
            if "@login_required" in source:
                hints.append("login_required_decorator")
            if "LoginRequiredMixin" in source:
                hints.append("login_required_mixin")

        except (OSError, TypeError):
            # Source not available or not a Python function
            pass

        return hints

    def _is_django_cbv(self, func: Any) -> bool:
        """
        Determine if a view function is a Django class-based view (CBV).
        Django CBVs have view_class but no DRF-specific attributes.
        """
        if not hasattr(func, "view_class"):
            return False

        view_class = func.view_class

        # Check if it's DRF by looking for DRF-specific attributes
        has_drf_permissions = hasattr(view_class, "permission_classes")
        has_drf_auth = hasattr(view_class, "authentication_classes")
        has_drf_renderer = hasattr(view_class, "renderer_classes")
        has_drf_parser = hasattr(view_class, "parser_classes")

        # If it has any DRF-specific attributes, it's likely DRF
        if has_drf_permissions or has_drf_auth or has_drf_renderer or has_drf_parser:
            return False

        # Check if the view_class inherits from Django's base views
        try:
            # Check if view_class is actually a class (not an instance)
            if inspect.isclass(view_class):
                mro = inspect.getmro(view_class)
            else:
                # It's an instance, check its class
                view_class_type = type(view_class)
                mro = inspect.getmro(view_class_type)

            for base_class in mro:
                # Check for Django views by module name
                if (
                    hasattr(base_class, "__module__")
                    and base_class.__module__
                    and "django.views" in base_class.__module__
                ):
                    return True
                # Check for Django auth mixins
                class_name = base_class.__name__
                if any(
                    mixin in class_name
                    for mixin in [
                        "LoginRequired",
                        "PermissionRequired",
                        "UserPassesTest",
                    ]
                ):
                    return True
        except (TypeError, AttributeError):
            pass

        return False
