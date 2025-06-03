"""
Tests for CI mode functionality in ReportGeneratorService.

This module tests the CI mode operations and console output functionality.
"""

from datetime import datetime
from unittest.mock import patch

from django_access_inspector.services.models import (
    AnalysisResult,
    CIResult,
    Snapshot,
    UncheckedView,
)
from django_access_inspector.services.report_generator import ReportGeneratorService


class TestReportGeneratorServiceCIMode:
    """Test cases for ReportGeneratorService CI mode functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        self.report_generator = ReportGeneratorService()
        self.sample_analysis_result = AnalysisResult()

    def test_ci_mode_success(self):
        """Test successful CI mode execution."""
        mock_snapshot = Snapshot(
            version="1.0",
            timestamp=datetime(2025, 6, 1, 12, 0, 0),
            unauthenticated_endpoints=[],
            unchecked_endpoints=[],
        )

        mock_ci_result = CIResult(
            success=True,
            message="CI check passed: no new security issues detected",
        )

        # Patch the snapshot service instance methods
        with (
            patch.object(
                self.report_generator.snapshot_service,
                "load_snapshot",
                return_value=mock_snapshot,
            ) as mock_load,
            patch.object(
                self.report_generator.snapshot_service,
                "compare_with_snapshot",
                return_value=mock_ci_result,
            ) as mock_compare,
        ):
            # Execute CI mode
            result = self.report_generator.ci_mode(
                self.sample_analysis_result, "snapshot.json"
            )

            # Verify calls
            mock_load.assert_called_once_with("snapshot.json")
            mock_compare.assert_called_once_with(
                self.sample_analysis_result, mock_snapshot
            )

            # Verify result
            assert result.success is True
            assert result.message == "CI check passed: no new security issues detected"

    def test_ci_mode_failure_with_new_issues(self):
        """Test CI mode with new security issues."""
        mock_snapshot = Snapshot(
            version="1.0",
            timestamp=datetime(2025, 6, 1, 12, 0, 0),
            unauthenticated_endpoints=[],
            unchecked_endpoints=[],
        )

        mock_ci_result = CIResult(
            success=False,
            new_unauthenticated_endpoints=["api/new-endpoint"],
            new_unchecked_endpoints=[UncheckedView(view="new.view", cause="error")],
            message="CI check failed: new security issues found",
        )

        with (
            patch.object(
                self.report_generator.snapshot_service,
                "load_snapshot",
                return_value=mock_snapshot,
            ),
            patch.object(
                self.report_generator.snapshot_service,
                "compare_with_snapshot",
                return_value=mock_ci_result,
            ),
        ):
            # Execute CI mode
            result = self.report_generator.ci_mode(
                self.sample_analysis_result, "snapshot.json"
            )

            # Verify result
            assert result.success is False
            assert len(result.new_unauthenticated_endpoints) == 1
            assert len(result.new_unchecked_endpoints) == 1

    def test_ci_mode_snapshot_not_found(self):
        """Test CI mode when snapshot file is not found."""
        with patch.object(
            self.report_generator.snapshot_service,
            "load_snapshot",
            side_effect=FileNotFoundError("File not found"),
        ):
            # Execute CI mode
            result = self.report_generator.ci_mode(
                self.sample_analysis_result, "nonexistent.json"
            )

            # Verify result
            assert result.success is False
            assert "Snapshot file not found" in result.message

    def test_ci_mode_invalid_snapshot(self):
        """Test CI mode with invalid snapshot file."""
        with patch.object(
            self.report_generator.snapshot_service,
            "load_snapshot",
            side_effect=ValueError("Invalid snapshot format"),
        ):
            # Execute CI mode
            result = self.report_generator.ci_mode(
                self.sample_analysis_result, "invalid.json"
            )

            # Verify result
            assert result.success is False
            assert "Invalid snapshot file" in result.message

    def test_print_ci_success(self):
        """Test printing successful CI results."""
        # Capture console output
        with patch.object(self.report_generator.console, "print") as mock_print:
            self.report_generator._print_ci_success()

            # Verify console output
            mock_print.assert_called_once()
            args = mock_print.call_args[0]
            panel = args[0]

            # Check panel properties
            assert panel.title == "CI Mode Results"
            assert panel.style == "green"
            assert "✓ CI check passed" in panel.renderable

    def test_print_ci_failure_with_unauthenticated(self):
        """Test printing CI failure with unauthenticated endpoints."""
        ci_result = CIResult(
            success=False,
            new_unauthenticated_endpoints=["api/endpoint1", "api/endpoint2"],
            message="Failed",
        )

        with patch.object(self.report_generator.console, "print") as mock_print:
            self.report_generator._print_ci_failure(ci_result)

            # Verify console output
            mock_print.assert_called_once()
            args = mock_print.call_args[0]
            panel = args[0]

            # Check panel properties
            assert panel.title == "CI Mode Results - Security Issues Detected"
            assert panel.style == "red"

            # Check panel content - it should be a string with the formatted details
            content = panel.renderable
            assert "2 new unauthenticated endpoint(s)" in content
            assert "api/endpoint1" in content
            assert "api/endpoint2" in content

    def test_print_ci_failure_with_unchecked(self):
        """Test printing CI failure with unchecked endpoints."""
        ci_result = CIResult(
            success=False,
            new_unchecked_endpoints=[
                UncheckedView(view="view1", cause="error1"),
                UncheckedView(view="view2", cause="error2"),
            ],
            message="Failed",
        )

        with patch.object(self.report_generator.console, "print") as mock_print:
            self.report_generator._print_ci_failure(ci_result)

            # Verify console output
            mock_print.assert_called_once()
            args = mock_print.call_args[0]
            panel = args[0]

            # Check panel content
            content = panel.renderable
            assert "2 new unchecked endpoint(s)" in content
            assert "view1 (error1)" in content
            assert "view2 (error2)" in content

    def test_print_ci_failure_with_removed(self):
        """Test printing CI failure with removed endpoints."""
        ci_result = CIResult(
            success=False,
            new_unauthenticated_endpoints=["api/new"],
            removed_endpoints=["api/old1", "api/old2"],
            message="Failed",
        )

        with patch.object(self.report_generator.console, "print") as mock_print:
            self.report_generator._print_ci_failure(ci_result)

            # Verify console output
            mock_print.assert_called_once()
            args = mock_print.call_args[0]
            panel = args[0]

            # Check panel content
            content = panel.renderable
            assert "2 endpoint(s) removed" in content
            assert "api/old1" in content
            assert "api/old2" in content

    def test_print_ci_error(self):
        """Test printing CI error messages."""
        with patch.object(self.report_generator.console, "print") as mock_print:
            self.report_generator._print_ci_error("Test error", "Additional info")

            # Verify console output
            mock_print.assert_called_once()
            args = mock_print.call_args[0]
            panel = args[0]

            # Check panel properties
            assert panel.title == "CI Mode Error"
            assert panel.style == "red"

            # Check panel content
            content = panel.renderable
            assert "Test error" in content
            assert "Additional info" in content

    def test_print_ci_error_without_additional_info(self):
        """Test printing CI error without additional info."""
        with patch.object(self.report_generator.console, "print") as mock_print:
            self.report_generator._print_ci_error("Test error")

            # Verify console output
            mock_print.assert_called_once()
            args = mock_print.call_args[0]
            panel = args[0]

            # Check panel content
            content = panel.renderable
            assert "Test error" in content

    def test_add_unauthenticated_details_empty(self):
        """Test adding unauthenticated details when list is empty."""
        ci_result = CIResult(success=True, new_unauthenticated_endpoints=[])
        failure_details = []

        self.report_generator._add_unauthenticated_details(ci_result, failure_details)

        assert len(failure_details) == 0

    def test_add_unauthenticated_details_with_endpoints(self):
        """Test adding unauthenticated details with endpoints."""
        ci_result = CIResult(
            success=False,
            new_unauthenticated_endpoints=["api/endpoint1", "api/endpoint2"],
        )
        failure_details = []

        self.report_generator._add_unauthenticated_details(ci_result, failure_details)

        assert len(failure_details) == 3  # Header + 2 endpoints
        assert "2 new unauthenticated endpoint(s)" in failure_details[0]
        assert "api/endpoint1" in failure_details[1]
        assert "api/endpoint2" in failure_details[2]

    def test_add_unchecked_details_empty(self):
        """Test adding unchecked details when list is empty."""
        ci_result = CIResult(success=True, new_unchecked_endpoints=[])
        failure_details = []

        self.report_generator._add_unchecked_details(ci_result, failure_details)

        assert len(failure_details) == 0

    def test_add_unchecked_details_with_endpoints(self):
        """Test adding unchecked details with endpoints."""
        ci_result = CIResult(
            success=False,
            new_unchecked_endpoints=[
                UncheckedView(view="view1", cause="error1"),
                UncheckedView(view="view2", cause="error2"),
            ],
        )
        failure_details = []

        self.report_generator._add_unchecked_details(ci_result, failure_details)

        assert len(failure_details) == 3  # Header + 2 endpoints
        assert "2 new unchecked endpoint(s)" in failure_details[0]
        assert "view1 (error1)" in failure_details[1]
        assert "view2 (error2)" in failure_details[2]

    def test_add_removed_details_empty(self):
        """Test adding removed details when list is empty."""
        ci_result = CIResult(success=True, removed_endpoints=[])
        failure_details = []

        self.report_generator._add_removed_details(ci_result, failure_details)

        assert len(failure_details) == 0

    def test_add_removed_details_with_endpoints(self):
        """Test adding removed details with endpoints."""
        ci_result = CIResult(
            success=False,
            removed_endpoints=["api/old1", "api/old2"],
        )
        failure_details = []

        self.report_generator._add_removed_details(ci_result, failure_details)

        assert len(failure_details) == 3  # Header + 2 endpoints
        assert "2 endpoint(s) removed" in failure_details[0]
        assert "api/old1" in failure_details[1]
        assert "api/old2" in failure_details[2]

    def test_ci_mode_integration(self):
        """Test complete CI mode integration."""
        mock_snapshot = Snapshot(
            version="1.0",
            timestamp=datetime(2025, 6, 1, 12, 0, 0),
            unauthenticated_endpoints=["api/old"],
            unchecked_endpoints=[],
        )

        mock_ci_result = CIResult(
            success=False,
            new_unauthenticated_endpoints=["api/new"],
            removed_endpoints=["api/old"],
            message="New endpoints detected",
        )

        with (
            patch.object(
                self.report_generator.snapshot_service,
                "load_snapshot",
                return_value=mock_snapshot,
            ) as mock_load,
            patch.object(
                self.report_generator.snapshot_service,
                "compare_with_snapshot",
                return_value=mock_ci_result,
            ) as mock_compare,
            patch.object(self.report_generator.console, "print") as mock_print,
        ):
            result = self.report_generator.ci_mode(
                self.sample_analysis_result, "test.json"
            )

            # Verify snapshot operations
            mock_load.assert_called_once_with("test.json")
            mock_compare.assert_called_once()

            # Verify console output was called
            mock_print.assert_called()

            # Verify result
            assert result.success is False
            assert len(result.new_unauthenticated_endpoints) == 1
