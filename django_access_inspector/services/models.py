"""
Data models for service communication in Django Access Inspector.

These dataclasses define the structure for data exchange between services
during the access control inspection process.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


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


@dataclass
class Snapshot:
    """Snapshot of security baseline for CI mode."""

    version: str
    timestamp: datetime
    unauthenticated_endpoints: List[str] = field(default_factory=list)
    unchecked_endpoints: List[UncheckedView] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert snapshot to dictionary for JSON serialization."""
        return {
            "version": self.version,
            "timestamp": self.timestamp.isoformat(),
            "unauthenticated_endpoints": self.unauthenticated_endpoints,
            "unchecked_endpoints": [
                {"view": uv.view, "cause": uv.cause} for uv in self.unchecked_endpoints
            ],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Snapshot":
        """Create snapshot from dictionary loaded from JSON."""
        return cls(
            version=data["version"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            unauthenticated_endpoints=data["unauthenticated_endpoints"],
            unchecked_endpoints=[
                UncheckedView(view=uv["view"], cause=uv["cause"])
                for uv in data["unchecked_endpoints"]
            ],
        )


@dataclass
class CIResult:
    """Result of CI mode comparison."""

    success: bool
    new_unauthenticated_endpoints: List[str] = field(default_factory=list)
    new_unchecked_endpoints: List[UncheckedView] = field(default_factory=list)
    removed_endpoints: List[str] = field(default_factory=list)
    message: str = ""

    @property
    def has_new_security_issues(self) -> bool:
        """Check if there are new security issues."""
        return (
            len(self.new_unauthenticated_endpoints) > 0
            or len(self.new_unchecked_endpoints) > 0
        )

    @property
    def exit_code(self) -> int:
        """Get appropriate exit code for CI systems."""
        return 0 if self.success else 1
