"""
Integration tests for CI mode functionality.

This module tests the complete CI workflow end-to-end.
"""

import json
import tempfile
from datetime import datetime
from pathlib import Path
from unittest.mock import Mock, patch

from django_access_inspector.services import (
    ReportGeneratorService,
    SnapshotService,
)
from django_access_inspector.services.models import (
    AnalysisResult,
    SplitViews,
    UncheckedView,
    ViewInspectionResult,
)


class TestCIModeIntegration:
    """Integration tests for complete CI mode workflow."""

    def setup_method(self):
        """Set up test fixtures."""
        self.snapshot_service = SnapshotService()
        self.report_generator = ReportGeneratorService()

    def create_sample_analysis_result(
        self, include_unauthenticated=True, include_unchecked=True
    ):
        """Create a sample analysis result for testing."""
        views = {
            "api/authenticated": ViewInspectionResult(
                url_name="auth_endpoint",
                permission_classes=["IsAuthenticated"],
                authentication_classes=["SessionAuthentication"],
            ),
        }

        if include_unauthenticated:
            views["api/public"] = ViewInspectionResult(
                url_name="public_endpoint",
                permission_classes=[],
                authentication_classes=[],
            )

        unchecked_views = []
        if include_unchecked:
            unchecked_views = [
                UncheckedView(view="problematic.view", cause="import error"),
            ]

        return AnalysisResult(
            views=views,
            admin_views=["admin/users"],
            unchecked_views=unchecked_views,
        )

    @patch("django_access_inspector.services.snapshot.ViewInspectorService")
    def test_complete_snapshot_workflow(self, mock_view_inspector_class):
        """Test complete snapshot save and load workflow."""
        # Mock ViewInspectorService for snapshot service
        mock_view_inspector = Mock()
        mock_view_inspector_class.return_value = mock_view_inspector

        mock_split_views = SplitViews(
            unauthenticated={"api/public": ViewInspectionResult(url_name="public")},
            authenticated={"api/auth": ViewInspectionResult(url_name="auth")},
        )
        mock_view_inspector.split_views_by_authentication.return_value = (
            mock_split_views
        )

        analysis_result = self.create_sample_analysis_result()

        with tempfile.TemporaryDirectory() as temp_dir:
            snapshot_path = Path(temp_dir) / "test_snapshot.json"

            # Save snapshot
            self.snapshot_service.save_snapshot(analysis_result, str(snapshot_path))

            # Verify file exists
            assert snapshot_path.exists()

            # Load snapshot
            loaded_snapshot = self.snapshot_service.load_snapshot(str(snapshot_path))

            # Verify snapshot content
            assert loaded_snapshot.version == "1.0"
            assert loaded_snapshot.unauthenticated_endpoints == ["api/public"]
            assert len(loaded_snapshot.unchecked_endpoints) == 1
            assert loaded_snapshot.unchecked_endpoints[0].view == "problematic.view"

    @patch("django_access_inspector.services.snapshot.ViewInspectorService")
    def test_ci_mode_no_changes(self, mock_view_inspector_class):
        """Test CI mode when there are no changes from snapshot."""
        # Mock ViewInspectorService
        mock_view_inspector = Mock()
        mock_view_inspector_class.return_value = mock_view_inspector

        mock_split_views = SplitViews(
            unauthenticated={"api/public": ViewInspectionResult(url_name="public")},
        )
        mock_view_inspector.split_views_by_authentication.return_value = (
            mock_split_views
        )

        analysis_result = self.create_sample_analysis_result()

        with tempfile.TemporaryDirectory() as temp_dir:
            snapshot_path = Path(temp_dir) / "baseline.json"

            # Create baseline snapshot
            self.snapshot_service.save_snapshot(analysis_result, str(snapshot_path))

            # Run CI mode against same data
            ci_result = self.report_generator.ci_mode(
                analysis_result, str(snapshot_path)
            )

            # Should pass with no changes
            assert ci_result.success is True
            assert len(ci_result.new_unauthenticated_endpoints) == 0
            assert len(ci_result.new_unchecked_endpoints) == 0
            assert "no new security issues detected" in ci_result.message

    @patch("django_access_inspector.services.snapshot.ViewInspectorService")
    def test_ci_mode_new_security_issues(self, mock_view_inspector_class):
        """Test CI mode when new security issues are detected."""
        # Mock ViewInspectorService
        mock_view_inspector = Mock()
        mock_view_inspector_class.return_value = mock_view_inspector

        # Create baseline (no issues)
        baseline_result = self.create_sample_analysis_result(
            include_unauthenticated=False, include_unchecked=False
        )

        mock_split_views_baseline = SplitViews(unauthenticated={})
        mock_view_inspector.split_views_by_authentication.return_value = (
            mock_split_views_baseline
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            snapshot_path = Path(temp_dir) / "baseline.json"

            # Create baseline snapshot
            self.snapshot_service.save_snapshot(baseline_result, str(snapshot_path))

            # Now mock for current analysis (with new issues)
            current_result = self.create_sample_analysis_result(
                include_unauthenticated=True, include_unchecked=True
            )

            mock_split_views_current = SplitViews(
                unauthenticated={"api/public": ViewInspectionResult(url_name="public")},
            )
            mock_view_inspector.split_views_by_authentication.return_value = (
                mock_split_views_current
            )

            # Run CI mode
            ci_result = self.report_generator.ci_mode(
                current_result, str(snapshot_path)
            )

            # Should fail with new issues
            assert ci_result.success is False
            assert len(ci_result.new_unauthenticated_endpoints) == 1
            assert "api/public" in ci_result.new_unauthenticated_endpoints
            assert len(ci_result.new_unchecked_endpoints) == 1
            assert ci_result.new_unchecked_endpoints[0].view == "problematic.view"

    def test_ci_mode_missing_snapshot(self):
        """Test CI mode when snapshot file is missing."""
        analysis_result = self.create_sample_analysis_result()

        ci_result = self.report_generator.ci_mode(
            analysis_result, "/nonexistent/snapshot.json"
        )

        assert ci_result.success is False
        assert "Snapshot file not found" in ci_result.message

    def test_ci_mode_invalid_snapshot(self):
        """Test CI mode with malformed snapshot file."""
        analysis_result = self.create_sample_analysis_result()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("invalid json content {")
            temp_path = f.name

        try:
            ci_result = self.report_generator.ci_mode(analysis_result, temp_path)

            assert ci_result.success is False
            assert "Invalid snapshot file" in ci_result.message

        finally:
            Path(temp_path).unlink()

    @patch("django_access_inspector.services.snapshot.ViewInspectorService")
    def test_snapshot_format_validation(self, mock_view_inspector_class):
        """Test that snapshot files have the expected format."""
        # Mock ViewInspectorService
        mock_view_inspector = Mock()
        mock_view_inspector_class.return_value = mock_view_inspector

        mock_split_views = SplitViews(
            unauthenticated={"api/public": ViewInspectionResult(url_name="public")},
        )
        mock_view_inspector.split_views_by_authentication.return_value = (
            mock_split_views
        )

        analysis_result = self.create_sample_analysis_result()

        with tempfile.TemporaryDirectory() as temp_dir:
            snapshot_path = Path(temp_dir) / "format_test.json"

            # Save snapshot
            self.snapshot_service.save_snapshot(analysis_result, str(snapshot_path))

            # Read and validate JSON structure
            with snapshot_path.open() as f:
                data = json.load(f)

            # Validate required fields
            required_fields = [
                "version",
                "timestamp",
                "unauthenticated_endpoints",
                "unchecked_endpoints",
            ]
            for field in required_fields:
                assert field in data, f"Missing required field: {field}"

            # Validate field types
            assert isinstance(data["version"], str)
            assert isinstance(data["timestamp"], str)
            assert isinstance(data["unauthenticated_endpoints"], list)
            assert isinstance(data["unchecked_endpoints"], list)

            # Validate timestamp format
            datetime.fromisoformat(data["timestamp"])  # Should not raise

            # Validate unchecked endpoints structure
            for unchecked in data["unchecked_endpoints"]:
                assert "view" in unchecked
                assert "cause" in unchecked
                assert isinstance(unchecked["view"], str)
                assert isinstance(unchecked["cause"], str)

    @patch("django_access_inspector.services.snapshot.ViewInspectorService")
    def test_ci_mode_removed_endpoints(self, mock_view_inspector_class):
        """Test CI mode behavior when endpoints are removed."""
        # Mock ViewInspectorService
        mock_view_inspector = Mock()
        mock_view_inspector_class.return_value = mock_view_inspector

        # Create baseline with multiple endpoints
        baseline_views = {
            "api/endpoint1": ViewInspectionResult(url_name="ep1"),
            "api/endpoint2": ViewInspectionResult(
                url_name="ep2", permission_classes=[]
            ),
            "api/endpoint3": ViewInspectionResult(
                url_name="ep3", permission_classes=[]
            ),
        }
        baseline_result = AnalysisResult(views=baseline_views, unchecked_views=[])

        mock_split_views_baseline = SplitViews(
            unauthenticated={
                "api/endpoint2": baseline_views["api/endpoint2"],
                "api/endpoint3": baseline_views["api/endpoint3"],
            },
        )
        mock_view_inspector.split_views_by_authentication.return_value = (
            mock_split_views_baseline
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            snapshot_path = Path(temp_dir) / "baseline.json"

            # Create baseline snapshot
            self.snapshot_service.save_snapshot(baseline_result, str(snapshot_path))

            # Create current state with some endpoints removed
            current_views = {"api/endpoint1": ViewInspectionResult(url_name="ep1")}
            current_result = AnalysisResult(views=current_views, unchecked_views=[])

            mock_split_views_current = SplitViews(unauthenticated={})
            mock_view_inspector.split_views_by_authentication.return_value = (
                mock_split_views_current
            )

            # Run CI mode
            ci_result = self.report_generator.ci_mode(
                current_result, str(snapshot_path)
            )

            # Should pass (removed endpoints don't fail CI)
            assert ci_result.success is True
            assert len(ci_result.removed_endpoints) == 2
            assert "api/endpoint2" in ci_result.removed_endpoints
            assert "api/endpoint3" in ci_result.removed_endpoints

    @patch("django_access_inspector.services.snapshot.ViewInspectorService")
    def test_ci_mode_mixed_changes(self, mock_view_inspector_class):
        """Test CI mode with mixed changes (new, removed, unchanged)."""
        # Mock ViewInspectorService
        mock_view_inspector = Mock()
        mock_view_inspector_class.return_value = mock_view_inspector

        # Create baseline
        baseline_views = {
            "api/old": ViewInspectionResult(url_name="old", permission_classes=[]),
            "api/unchanged": ViewInspectionResult(
                url_name="unchanged", permission_classes=[]
            ),
        }
        baseline_result = AnalysisResult(
            views=baseline_views,
            unchecked_views=[UncheckedView(view="old.unchecked", cause="old error")],
        )

        mock_split_views_baseline = SplitViews(
            unauthenticated={
                "api/old": baseline_views["api/old"],
                "api/unchanged": baseline_views["api/unchanged"],
            },
        )
        mock_view_inspector.split_views_by_authentication.return_value = (
            mock_split_views_baseline
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            snapshot_path = Path(temp_dir) / "baseline.json"

            # Create baseline snapshot
            self.snapshot_service.save_snapshot(baseline_result, str(snapshot_path))

            # Create current state with mixed changes
            current_views = {
                "api/unchanged": ViewInspectionResult(
                    url_name="unchanged", permission_classes=[]
                ),
                "api/new": ViewInspectionResult(url_name="new", permission_classes=[]),
            }
            current_result = AnalysisResult(
                views=current_views,
                unchecked_views=[
                    UncheckedView(view="old.unchecked", cause="old error"),
                    UncheckedView(view="new.unchecked", cause="new error"),
                ],
            )

            mock_split_views_current = SplitViews(
                unauthenticated={
                    "api/unchanged": current_views["api/unchanged"],
                    "api/new": current_views["api/new"],
                },
            )
            mock_view_inspector.split_views_by_authentication.return_value = (
                mock_split_views_current
            )

            # Run CI mode
            ci_result = self.report_generator.ci_mode(
                current_result, str(snapshot_path)
            )

            # Should fail due to new endpoints
            assert ci_result.success is False
            assert len(ci_result.new_unauthenticated_endpoints) == 1
            assert "api/new" in ci_result.new_unauthenticated_endpoints
            assert len(ci_result.new_unchecked_endpoints) == 1
            assert ci_result.new_unchecked_endpoints[0].view == "new.unchecked"
            assert len(ci_result.removed_endpoints) == 1
            assert "api/old" in ci_result.removed_endpoints

    def test_snapshot_version_consistency(self):
        """Test that snapshot version is consistent."""
        assert self.snapshot_service.SNAPSHOT_VERSION == "1.0"

        # Test that version is included in snapshots
        analysis_result = self.create_sample_analysis_result()

        with tempfile.TemporaryDirectory() as temp_dir:
            snapshot_path = Path(temp_dir) / "version_test.json"

            with patch(
                "django_access_inspector.services.snapshot.ViewInspectorService"
            ):
                self.snapshot_service.save_snapshot(analysis_result, str(snapshot_path))

            with snapshot_path.open() as f:
                data = json.load(f)

            assert data["version"] == "1.0"
