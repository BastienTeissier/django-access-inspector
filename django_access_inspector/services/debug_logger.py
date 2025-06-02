"""
Debug logging utilities for Django Access Inspector.

This module provides configurable debug logging functionality to help
debug authentication detection issues.
"""

import logging
import sys
from typing import Any, Dict, List, Optional


class DebugLogger:
    """Centralized debug logger for Django Access Inspector."""

    def __init__(self, enabled: bool = False):
        self.enabled = enabled
        self.logger = logging.getLogger("django_access_inspector.debug")

        if enabled:
            self._setup_debug_logging()

    def _setup_debug_logging(self) -> None:
        """Setup debug logging configuration."""
        # Remove existing handlers to avoid duplicates
        self.logger.handlers.clear()

        # Create console handler with detailed formatting
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter("[DEBUG] %(name)s - %(message)s")
        handler.setFormatter(formatter)

        # Set debug level and add handler
        self.logger.setLevel(logging.DEBUG)
        self.logger.addHandler(handler)

        # Prevent propagation to avoid duplicate logs
        self.logger.propagate = False

    def log_url_pattern_extraction(
        self,
        pattern_type: str,
        pattern: Any,
        base: str = "",
        namespace: Optional[str] = None,
    ) -> None:
        """Log URL pattern extraction details."""
        if not self.enabled:
            return

        self.logger.debug(f"URL_EXTRACTION: Found {pattern_type}")
        self.logger.debug(f"  - Pattern: {pattern}")
        self.logger.debug(f"  - Base: '{base}'")
        self.logger.debug(f"  - Namespace: {namespace}")
        if hasattr(pattern, "name"):
            self.logger.debug(f"  - Name: {getattr(pattern, 'name', None)}")

    def log_view_function_found(
        self, view_func: Any, pattern: str, name: Optional[str]
    ) -> None:
        """Log when a view function is successfully extracted."""
        if not self.enabled:
            return

        callback_info = self._get_callback_info(view_func)
        self.logger.debug(f"VIEW_FOUND: {name or 'unnamed'}")
        self.logger.debug(f"  - Pattern: {pattern}")
        self.logger.debug(f"  - Callback: {callback_info['name']}")
        self.logger.debug(f"  - Type: {callback_info['type']}")
        self.logger.debug(f"  - Module: {callback_info['module']}")

    def log_view_inspection_start(
        self, view_func: Any, pattern: str, name: Optional[str]
    ) -> None:
        """Log the start of view function inspection."""
        if not self.enabled:
            return

        callback_info = self._get_callback_info(view_func)
        self.logger.debug(f"INSPECT_START: {name or 'unnamed'}")
        self.logger.debug(f"  - Pattern: {pattern}")
        self.logger.debug(f"  - Callback: {callback_info['name']}")
        self.logger.debug(f"  - Available attributes: {callback_info['attributes']}")

    def log_authentication_detection(
        self,
        view_func: Any,
        detection_path: str,
        permissions: List[str],
        authentications: List[str],
    ) -> None:
        """Log authentication detection results."""
        if not self.enabled:
            return

        callback_info = self._get_callback_info(view_func)
        self.logger.debug(f"AUTH_DETECTION: {callback_info['name']}")
        self.logger.debug(f"  - Detection path: {detection_path}")
        self.logger.debug(f"  - Permission classes: {permissions}")
        self.logger.debug(f"  - Authentication classes: {authentications}")

    def log_django_auth_analysis(
        self,
        view_func: Any,
        decorators: List[str],
        mixins: List[str],
        middleware_hints: List[str],
    ) -> None:
        """Log Django-native authentication analysis."""
        if not self.enabled:
            return

        callback_info = self._get_callback_info(view_func)
        self.logger.debug(f"DJANGO_AUTH_ANALYSIS: {callback_info['name']}")
        self.logger.debug(f"  - Decorators found: {decorators}")
        self.logger.debug(f"  - Mixins found: {mixins}")
        self.logger.debug(f"  - Middleware hints: {middleware_hints}")

    def log_categorization_decision(
        self,
        view_name: Optional[str],
        decision: str,
        reason: str,
        supporting_evidence: List[str],
    ) -> None:
        """Log why a view was categorized in a specific way."""
        if not self.enabled:
            return

        self.logger.debug(f"CATEGORIZATION: {view_name or 'unnamed'}")
        self.logger.debug(f"  - Decision: {decision}")
        self.logger.debug(f"  - Reason: {reason}")
        for evidence in supporting_evidence:
            self.logger.debug(f"  - Evidence: {evidence}")

    def log_unchecked_view(
        self, view_info: str, cause: str, analysis_attempted: bool
    ) -> None:
        """Log details about unchecked views."""
        if not self.enabled:
            return

        self.logger.debug(f"UNCHECKED_VIEW: {view_info}")
        self.logger.debug(f"  - Cause: {cause}")
        self.logger.debug(f"  - Analysis attempted: {analysis_attempted}")

    def log_admin_view_detection(
        self, view_name: Optional[str], detection_method: str
    ) -> None:
        """Log admin view detection."""
        if not self.enabled:
            return

        self.logger.debug(f"ADMIN_VIEW: {view_name or 'unnamed'}")
        self.logger.debug(f"  - Detection method: {detection_method}")

    def _get_callback_info(self, callback: Any) -> Dict[str, Any]:
        """Extract detailed information about a callback function."""
        info = {
            "name": "unknown",
            "type": "unknown",
            "module": "unknown",
            "attributes": [],
        }

        try:
            # Get function/class name
            if hasattr(callback, "__name__"):
                info["name"] = callback.__name__
            elif hasattr(callback, "__class__"):
                info["name"] = f"{callback.__class__.__name__}()"
            else:
                info["name"] = str(callback)

            # Get module information
            if hasattr(callback, "__module__"):
                info["module"] = callback.__module__

            # Determine type
            if hasattr(callback, "view_class"):
                info["type"] = "DRF function-based view (@api_view)"
            elif hasattr(callback, "cls"):
                info["type"] = "DRF class-based view"
                if hasattr(callback.cls, "__name__"):
                    info["name"] = callback.cls.__name__
            elif hasattr(callback, "__self__") and hasattr(
                callback.__self__, "__class__"
            ):
                info["type"] = "bound method"
            elif callable(callback):
                if (
                    hasattr(callback, "__class__")
                    and callback.__class__.__name__ != "function"
                ):
                    info["type"] = "callable class instance"
                else:
                    info["type"] = "function"

            # Get available attributes
            info["attributes"] = [
                attr
                for attr in dir(callback)
                if not attr.startswith("_")
                or attr in ["__name__", "__module__", "__doc__"]
            ]

        except Exception:
            # Fallback to basic string representation
            info["name"] = str(callback)

        return info


# Global debug logger instance
_debug_logger: Optional[DebugLogger] = None


def get_debug_logger() -> DebugLogger:
    """Get the global debug logger instance."""
    global _debug_logger
    if _debug_logger is None:
        _debug_logger = DebugLogger(enabled=False)
    return _debug_logger


def enable_debug_logging() -> None:
    """Enable debug logging globally."""
    global _debug_logger
    _debug_logger = DebugLogger(enabled=True)


def disable_debug_logging() -> None:
    """Disable debug logging globally."""
    global _debug_logger
    if _debug_logger:
        _debug_logger.enabled = False
