"""
View Inspector Service for Django Access Inspector.

This service handles the inspection of view functions to extract permission
and authentication class information.
"""

import re
import logging
from typing import List, Dict
from django.conf import settings

from .models import (
    ViewFunction,
    ViewInspectionResult,
    UncheckedView,
    AnalysisResult,
    DefaultClasses,
    SplitViews,
)

logger = logging.getLogger(__name__)


class ViewInspectorService:
    """Service responsible for inspecting views for permissions and authentication."""

    def inspect_view_function(self, view_func: ViewFunction) -> ViewInspectionResult:
        """
        Inspect a single view function to extract permission and authentication classes.

        Returns ViewInspectionResult with extracted classes, or raises exception for unchecked views.
        """
        func, _, url_name = view_func.callback, view_func.pattern, view_func.name

        permissions = []
        authentications = []

        # Check for model admin views
        if hasattr(func, "model_admin"):
            raise ValueError("model_admin")

        # Check for view_class attribute (function-based views with @api_view decorator)
        if hasattr(func, "view_class"):
            permissions.extend(
                [
                    getattr(permission_class, "__name__", "unknown")
                    for permission_class in getattr(
                        func.view_class, "permission_classes", []
                    )
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
            # Unknown function type - create descriptive name for unchecked view
            func_name = func
            if hasattr(func, "__name__"):
                func_name = func.__name__
            elif hasattr(func, "__class__"):
                func_name = f"{getattr(func.__class__, '__name__', 'unknown')}()"
            else:
                func_name = re.sub(r" at 0x[0-9a-f]+", "", repr(func))

            raise ValueError(f"unknown:{url_name} / {func_name}")

        return ViewInspectionResult(
            url_name=url_name,
            permission_classes=list(set(permissions)),
            authentication_classes=list(set(authentications)),
        )

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
        authenticated = {}
        unauthenticated = {}

        for url, view_result in views.items():
            if (
                len(view_result.authentication_classes) > 0
                or len(view_result.permission_classes) > 0
            ):
                authenticated[url] = view_result
            else:
                unauthenticated[url] = view_result

        return SplitViews(authenticated=authenticated, unauthenticated=unauthenticated)
