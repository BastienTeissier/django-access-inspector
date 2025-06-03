"""
Tests for data models in Django Access Inspector.

This module tests the dataclasses used for service communication,
particularly focusing on CI mode functionality.
"""

from datetime import datetime

from django_access_inspector.services.models import (
    AnalysisResult,
    CIResult,
    Snapshot,
    UncheckedView,
    ViewInspectionResult,
)


class TestSnapshot:
    """Test cases for Snapshot dataclass."""

    def test_snapshot_to_dict(self):
        """Test converting snapshot to dictionary."""
        timestamp = datetime(2025, 6, 1, 12, 0, 0)
        unchecked_views = [
            UncheckedView(view="test.view", cause="missing permissions"),
            UncheckedView(view="other.view", cause="invalid class"),
        ]

        snapshot = Snapshot(
            version="1.0",
            timestamp=timestamp,
            unauthenticated_endpoints=["api/public", "api/health"],
            unchecked_endpoints=unchecked_views,
        )

        result = snapshot.to_dict()

        expected = {
            "version": "1.0",
            "timestamp": "2025-06-01T12:00:00",
            "unauthenticated_endpoints": ["api/public", "api/health"],
            "unchecked_endpoints": [
                {"view": "test.view", "cause": "missing permissions"},
                {"view": "other.view", "cause": "invalid class"},
            ],
        }

        assert result == expected

    def test_snapshot_from_dict(self):
        """Test creating snapshot from dictionary."""
        data = {
            "version": "1.0",
            "timestamp": "2025-06-01T12:00:00",
            "unauthenticated_endpoints": ["api/public", "api/health"],
            "unchecked_endpoints": [
                {"view": "test.view", "cause": "missing permissions"},
                {"view": "other.view", "cause": "invalid class"},
            ],
        }

        snapshot = Snapshot.from_dict(data)

        assert snapshot.version == "1.0"
        assert snapshot.timestamp == datetime(2025, 6, 1, 12, 0, 0)
        assert snapshot.unauthenticated_endpoints == ["api/public", "api/health"]
        assert len(snapshot.unchecked_endpoints) == 2
        assert snapshot.unchecked_endpoints[0].view == "test.view"
        assert snapshot.unchecked_endpoints[0].cause == "missing permissions"

    def test_snapshot_roundtrip(self):
        """Test that to_dict and from_dict are inverse operations."""
        timestamp = datetime(2025, 6, 1, 12, 0, 0)
        original = Snapshot(
            version="1.0",
            timestamp=timestamp,
            unauthenticated_endpoints=["api/test"],
            unchecked_endpoints=[UncheckedView(view="test", cause="error")],
        )

        # Convert to dict and back
        data = original.to_dict()
        restored = Snapshot.from_dict(data)

        assert restored.version == original.version
        assert restored.timestamp == original.timestamp
        assert restored.unauthenticated_endpoints == original.unauthenticated_endpoints
        assert len(restored.unchecked_endpoints) == len(original.unchecked_endpoints)
        assert (
            restored.unchecked_endpoints[0].view == original.unchecked_endpoints[0].view
        )
        assert (
            restored.unchecked_endpoints[0].cause
            == original.unchecked_endpoints[0].cause
        )

    def test_snapshot_empty_lists(self):
        """Test snapshot with empty lists."""
        timestamp = datetime.now()
        snapshot = Snapshot(
            version="1.0",
            timestamp=timestamp,
            unauthenticated_endpoints=[],
            unchecked_endpoints=[],
        )

        data = snapshot.to_dict()
        restored = Snapshot.from_dict(data)

        assert restored.unauthenticated_endpoints == []
        assert restored.unchecked_endpoints == []


class TestCIResult:
    """Test cases for CIResult dataclass."""

    def test_ci_result_success(self):
        """Test successful CI result."""
        result = CIResult(
            success=True,
            message="All checks passed",
        )

        assert result.success is True
        assert result.has_new_security_issues is False
        assert result.exit_code == 0
        assert result.message == "All checks passed"

    def test_ci_result_failure_with_unauthenticated(self):
        """Test failed CI result with new unauthenticated endpoints."""
        result = CIResult(
            success=False,
            new_unauthenticated_endpoints=["api/new-endpoint"],
            message="New security issues found",
        )

        assert result.success is False
        assert result.has_new_security_issues is True
        assert result.exit_code == 1
        assert len(result.new_unauthenticated_endpoints) == 1

    def test_ci_result_failure_with_unchecked(self):
        """Test failed CI result with new unchecked endpoints."""
        unchecked_views = [UncheckedView(view="test.view", cause="error")]
        result = CIResult(
            success=False,
            new_unchecked_endpoints=unchecked_views,
            message="New unchecked endpoints found",
        )

        assert result.success is False
        assert result.has_new_security_issues is True
        assert result.exit_code == 1
        assert len(result.new_unchecked_endpoints) == 1

    def test_ci_result_failure_with_both(self):
        """Test failed CI result with both types of new issues."""
        unchecked_views = [UncheckedView(view="test.view", cause="error")]
        result = CIResult(
            success=False,
            new_unauthenticated_endpoints=["api/new"],
            new_unchecked_endpoints=unchecked_views,
            message="Multiple issues found",
        )

        assert result.success is False
        assert result.has_new_security_issues is True
        assert result.exit_code == 1

    def test_ci_result_no_new_issues_despite_failure(self):
        """Test that has_new_security_issues can be False even if success is False."""
        # This could happen if there are other types of failures
        result = CIResult(
            success=False,
            new_unauthenticated_endpoints=[],
            new_unchecked_endpoints=[],
            message="Other error occurred",
        )

        assert result.success is False
        assert result.has_new_security_issues is False
        assert result.exit_code == 1

    def test_ci_result_with_removed_endpoints(self):
        """Test CI result with removed endpoints (informational)."""
        result = CIResult(
            success=True,
            removed_endpoints=["api/old-endpoint"],
            message="Some endpoints were removed",
        )

        assert result.success is True
        assert result.has_new_security_issues is False
        assert result.exit_code == 0
        assert len(result.removed_endpoints) == 1

    def test_ci_result_defaults(self):
        """Test CI result with default values."""
        result = CIResult(success=True)

        assert result.success is True
        assert result.new_unauthenticated_endpoints == []
        assert result.new_unchecked_endpoints == []
        assert result.removed_endpoints == []
        assert result.message == ""
        assert result.has_new_security_issues is False
        assert result.exit_code == 0


class TestUncheckedView:
    """Test cases for UncheckedView dataclass."""

    def test_unchecked_view_creation(self):
        """Test creating UncheckedView."""
        view = UncheckedView(view="test.view", cause="missing import")

        assert view.view == "test.view"
        assert view.cause == "missing import"

    def test_unchecked_view_equality(self):
        """Test UncheckedView equality."""
        view1 = UncheckedView(view="test.view", cause="error")
        view2 = UncheckedView(view="test.view", cause="error")
        view3 = UncheckedView(view="other.view", cause="error")

        assert view1 == view2
        assert view1 != view3


class TestAnalysisResult:
    """Test cases for AnalysisResult dataclass."""

    def test_analysis_result_defaults(self):
        """Test AnalysisResult with default values."""
        result = AnalysisResult()

        assert result.views == {}
        assert result.admin_views == []
        assert result.unchecked_views == []

    def test_analysis_result_with_data(self):
        """Test AnalysisResult with actual data."""
        views = {
            "api/test": ViewInspectionResult(
                url_name="test",
                permission_classes=["IsAuthenticated"],
                authentication_classes=["SessionAuthentication"],
            )
        }
        unchecked = [UncheckedView(view="bad.view", cause="import error")]

        result = AnalysisResult(
            views=views,
            admin_views=["admin/users"],
            unchecked_views=unchecked,
        )

        assert len(result.views) == 1
        assert len(result.admin_views) == 1
        assert len(result.unchecked_views) == 1
        assert "api/test" in result.views
