"""
Data models for service communication in Django Access Inspector.

These dataclasses define the structure for data exchange between services
during the access control inspection process.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional


@dataclass
class ViewFunction:
    """Represents a view function extracted from URL patterns."""

    callback: Any
    pattern: str
    name: Optional[str]


@dataclass
class ViewInspectionResult:
    """Result of inspecting a single view for permissions and authentication."""

    url_name: Optional[str]
    permission_classes: List[str] = field(default_factory=list)
    authentication_classes: List[str] = field(default_factory=list)


@dataclass
class UncheckedView:
    """Represents a view that couldn't be inspected."""

    view: str
    cause: str


@dataclass
class AnalysisResult:
    """Complete analysis result from URL and view inspection."""

    views: Dict[str, ViewInspectionResult] = field(default_factory=dict)
    admin_views: List[str] = field(default_factory=list)
    unchecked_views: List[UncheckedView] = field(default_factory=list)


@dataclass
class SplitViews:
    """Views split by authentication status."""

    authenticated: Dict[str, ViewInspectionResult] = field(default_factory=dict)
    unauthenticated: Dict[str, ViewInspectionResult] = field(default_factory=dict)


@dataclass
class DefaultClasses:
    """Default authentication and permission classes from settings."""

    authentication: List[str] = field(default_factory=list)
    permission: List[str] = field(default_factory=list)
