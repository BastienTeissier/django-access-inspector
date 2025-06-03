"""
Tests for SnapshotService in Django Access Inspector.

This module tests the snapshot operations for CI mode functionality.
"""

import json
import tempfile
from datetime import datetime
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from django_access_inspector.services.models import (
    AnalysisResult,
    Snapshot,
    SplitViews,
    UncheckedView,
    ViewInspectionResult,
)
from django_access_inspector.services.snapshot import SnapshotService


class TestSnapshotService:
    """Test cases for SnapshotService."""

    def setup_method(self):
        """Set up test fixtures."""
        self.snapshot_service = SnapshotService()
        self.sample_analysis_result = AnalysisResult(
            views={
                "api/authenticated": ViewInspectionResult(
                    url_name="auth_endpoint",
                    permission_classes=["IsAuthenticated"],
                    authentication_classes=["SessionAuthentication"],
                ),
                "api/public": ViewInspectionResult(
                    url_name="public_endpoint",
                    permission_classes=[],
                    authentication_classes=[],
                ),
            },
            admin_views=["admin/users"],
            unchecked_views=[
                UncheckedView(view="bad.view", cause="import error"),
            ],
        )

    def test_load_snapshot_success(self):
        """Test successful snapshot loading."""
        snapshot_data = {
            "version": "1.0",
            "timestamp": "2025-06-01T12:00:00",
            "unauthenticated_endpoints": ["api/public"],
            "unchecked_endpoints": [{"view": "bad.view", "cause": "import error"}],
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(snapshot_data, f)
            temp_path = f.name

        try:
            snapshot = self.snapshot_service.load_snapshot(temp_path)

            assert snapshot.version == "1.0"
            assert snapshot.timestamp == datetime(2025, 6, 1, 12, 0, 0)
            assert snapshot.unauthenticated_endpoints == ["api/public"]
            assert len(snapshot.unchecked_endpoints) == 1
            assert snapshot.unchecked_endpoints[0].view == "bad.view"

        finally:
            Path(temp_path).unlink()

    def test_load_snapshot_file_not_found(self):
        """Test loading snapshot when file doesn't exist."""
        with pytest.raises(FileNotFoundError, match="Snapshot file not found"):
            self.snapshot_service.load_snapshot("/nonexistent/path.json")

    def test_load_snapshot_invalid_json(self):
        """Test loading snapshot with invalid JSON."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("invalid json content {")
            temp_path = f.name

        try:
            with pytest.raises(ValueError, match="Invalid JSON in snapshot file"):
                self.snapshot_service.load_snapshot(temp_path)
        finally:
            Path(temp_path).unlink()

    def test_load_snapshot_missing_required_fields(self):
        """Test loading snapshot with missing required fields."""
        incomplete_data = {
            "version": "1.0",
            # Missing timestamp, unauthenticated_endpoints, unchecked_endpoints
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(incomplete_data, f)
            temp_path = f.name

        try:
            with pytest.raises(ValueError, match="Missing required field in snapshot"):
                self.snapshot_service.load_snapshot(temp_path)
        finally:
            Path(temp_path).unlink()

    def test_load_snapshot_malformed_data(self):
        """Test loading snapshot with malformed data structure."""
        malformed_data = {
            "version": "1.0",
            "timestamp": "invalid-timestamp",
            "unauthenticated_endpoints": ["api/public"],
            "unchecked_endpoints": [{"view": "bad.view", "cause": "import error"}],
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(malformed_data, f)
            temp_path = f.name

        try:
            with pytest.raises(ValueError, match="Malformed snapshot file"):
                self.snapshot_service.load_snapshot(temp_path)
        finally:
            Path(temp_path).unlink()

    @patch("django_access_inspector.services.snapshot.ViewInspectorService")
    def test_save_snapshot_success(self, mock_view_inspector_class):
        """Test successful snapshot saving."""
        # Mock ViewInspectorService
        mock_view_inspector = Mock()
        mock_view_inspector_class.return_value = mock_view_inspector

        mock_split_views = SplitViews(
            authenticated={
                "api/authenticated": self.sample_analysis_result.views[
                    "api/authenticated"
                ]
            },
            unauthenticated={
                "api/public": self.sample_analysis_result.views["api/public"]
            },
        )
        mock_view_inspector.split_views_by_authentication.return_value = (
            mock_split_views
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            snapshot_path = Path(temp_dir) / "snapshot.json"

            self.snapshot_service.save_snapshot(
                self.sample_analysis_result, str(snapshot_path)
            )

            # Verify file was created
            assert snapshot_path.exists()

            # Verify content
            with snapshot_path.open() as f:
                data = json.load(f)

            assert data["version"] == "1.0"
            assert "timestamp" in data
            assert data["unauthenticated_endpoints"] == ["api/public"]
            assert len(data["unchecked_endpoints"]) == 1
            assert data["unchecked_endpoints"][0]["view"] == "bad.view"

    @patch("django_access_inspector.services.snapshot.ViewInspectorService")
    def test_save_snapshot_creates_directory(self, mock_view_inspector_class):
        """Test that save_snapshot creates parent directories."""
        # Mock ViewInspectorService
        mock_view_inspector = Mock()
        mock_view_inspector_class.return_value = mock_view_inspector
        mock_view_inspector.split_views_by_authentication.return_value = SplitViews()

        with tempfile.TemporaryDirectory() as temp_dir:
            nested_path = Path(temp_dir) / "nested" / "directory" / "snapshot.json"

            self.snapshot_service.save_snapshot(
                self.sample_analysis_result, str(nested_path)
            )

            assert nested_path.exists()
            assert nested_path.parent.exists()

    @patch("django_access_inspector.services.snapshot.ViewInspectorService")
    @patch("pathlib.Path.open", side_effect=OSError("Permission denied"))
    def test_save_snapshot_io_error(self, mock_open, mock_view_inspector_class):
        """Test save_snapshot with I/O error."""
        # Mock ViewInspectorService
        mock_view_inspector = Mock()
        mock_view_inspector_class.return_value = mock_view_inspector
        mock_view_inspector.split_views_by_authentication.return_value = SplitViews()

        with tempfile.TemporaryDirectory() as temp_dir:
            snapshot_path = Path(temp_dir) / "snapshot.json"

            with pytest.raises(ValueError, match="Failed to save snapshot"):
                self.snapshot_service.save_snapshot(
                    self.sample_analysis_result, str(snapshot_path)
                )

    @patch("django_access_inspector.services.snapshot.ViewInspectorService")
    def test_compare_with_snapshot_no_changes(self, mock_view_inspector_class):
        """Test comparison when there are no changes."""
        # Mock ViewInspectorService
        mock_view_inspector = Mock()
        mock_view_inspector_class.return_value = mock_view_inspector

        mock_split_views = SplitViews(
            unauthenticated={
                "api/public": self.sample_analysis_result.views["api/public"]
            },
        )
        mock_view_inspector.split_views_by_authentication.return_value = (
            mock_split_views
        )

        snapshot = Snapshot(
            version="1.0",
            timestamp=datetime.now(),
            unauthenticated_endpoints=["api/public"],
            unchecked_endpoints=[UncheckedView(view="bad.view", cause="import error")],
        )

        result = self.snapshot_service.compare_with_snapshot(
            self.sample_analysis_result, snapshot
        )

        assert result.success is True
        assert len(result.new_unauthenticated_endpoints) == 0
        assert len(result.new_unchecked_endpoints) == 0
        assert "no new security issues detected" in result.message

    @patch("django_access_inspector.services.snapshot.ViewInspectorService")
    def test_compare_with_snapshot_new_unauthenticated(self, mock_view_inspector_class):
        """Test comparison with new unauthenticated endpoints."""
        # Mock ViewInspectorService
        mock_view_inspector = Mock()
        mock_view_inspector_class.return_value = mock_view_inspector

        mock_split_views = SplitViews(
            unauthenticated={
                "api/public": self.sample_analysis_result.views["api/public"],
                "api/new-endpoint": ViewInspectionResult(url_name="new"),
            },
        )
        mock_view_inspector.split_views_by_authentication.return_value = (
            mock_split_views
        )

        snapshot = Snapshot(
            version="1.0",
            timestamp=datetime.now(),
            unauthenticated_endpoints=["api/public"],
            unchecked_endpoints=[],
        )

        result = self.snapshot_service.compare_with_snapshot(
            self.sample_analysis_result, snapshot
        )

        assert result.success is False
        assert len(result.new_unauthenticated_endpoints) == 1
        assert "api/new-endpoint" in result.new_unauthenticated_endpoints
        assert "new unauthenticated endpoint(s)" in result.message

    @patch("django_access_inspector.services.snapshot.ViewInspectorService")
    def test_compare_with_snapshot_new_unchecked(self, mock_view_inspector_class):
        """Test comparison with new unchecked endpoints."""
        # Mock ViewInspectorService
        mock_view_inspector = Mock()
        mock_view_inspector_class.return_value = mock_view_inspector

        mock_split_views = SplitViews(unauthenticated={})
        mock_view_inspector.split_views_by_authentication.return_value = (
            mock_split_views
        )

        analysis_with_new_unchecked = AnalysisResult(
            views={},
            unchecked_views=[
                UncheckedView(view="bad.view", cause="import error"),
                UncheckedView(view="new.view", cause="new error"),
            ],
        )

        snapshot = Snapshot(
            version="1.0",
            timestamp=datetime.now(),
            unauthenticated_endpoints=[],
            unchecked_endpoints=[UncheckedView(view="bad.view", cause="import error")],
        )

        result = self.snapshot_service.compare_with_snapshot(
            analysis_with_new_unchecked, snapshot
        )

        assert result.success is False
        assert len(result.new_unchecked_endpoints) == 1
        assert result.new_unchecked_endpoints[0].view == "new.view"
        assert "new unchecked endpoint(s)" in result.message

    @patch("django_access_inspector.services.snapshot.ViewInspectorService")
    def test_compare_with_snapshot_removed_endpoints(self, mock_view_inspector_class):
        """Test comparison with removed endpoints."""
        # Mock ViewInspectorService
        mock_view_inspector = Mock()
        mock_view_inspector_class.return_value = mock_view_inspector

        mock_split_views = SplitViews(unauthenticated={})  # No current endpoints
        mock_view_inspector.split_views_by_authentication.return_value = (
            mock_split_views
        )

        snapshot = Snapshot(
            version="1.0",
            timestamp=datetime.now(),
            unauthenticated_endpoints=["api/removed-endpoint"],
            unchecked_endpoints=[],
        )

        result = self.snapshot_service.compare_with_snapshot(
            AnalysisResult(views={}, unchecked_views=[]), snapshot
        )

        assert result.success is True  # Removed endpoints don't fail CI
        assert len(result.removed_endpoints) == 1
        assert "api/removed-endpoint" in result.removed_endpoints

    @patch("django_access_inspector.services.snapshot.ViewInspectorService")
    def test_compare_with_snapshot_both_new_and_removed(
        self, mock_view_inspector_class
    ):
        """Test comparison with both new and removed endpoints."""
        # Mock ViewInspectorService
        mock_view_inspector = Mock()
        mock_view_inspector_class.return_value = mock_view_inspector

        mock_split_views = SplitViews(
            unauthenticated={"api/new-endpoint": ViewInspectionResult(url_name="new")},
        )
        mock_view_inspector.split_views_by_authentication.return_value = (
            mock_split_views
        )

        analysis_with_changes = AnalysisResult(
            views={},
            unchecked_views=[UncheckedView(view="new.unchecked", cause="new error")],
        )

        snapshot = Snapshot(
            version="1.0",
            timestamp=datetime.now(),
            unauthenticated_endpoints=["api/old-endpoint"],
            unchecked_endpoints=[
                UncheckedView(view="old.unchecked", cause="old error")
            ],
        )

        result = self.snapshot_service.compare_with_snapshot(
            analysis_with_changes, snapshot
        )

        assert result.success is False
        assert len(result.new_unauthenticated_endpoints) == 1
        assert len(result.new_unchecked_endpoints) == 1
        assert len(result.removed_endpoints) == 1
        assert "new unauthenticated endpoint(s)" in result.message
        assert "new unchecked endpoint(s)" in result.message
