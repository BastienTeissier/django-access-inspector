"""
Tests for command line interface CI mode functionality.

This module tests the management command's CI mode and snapshot operations.
"""

from io import StringIO
from unittest.mock import Mock, patch

import pytest
from django.core.management import call_command
from django.test import TestCase

from django_access_inspector.management.commands.inspect_access_control import Command
from django_access_inspector.services.models import (
    AnalysisResult,
    CIResult,
    ViewFunction,
)


class TestInspectAccessControlCommand(TestCase):
    """Test cases for inspect_access_control management command."""

    def setUp(self):
        """Set up test fixtures."""
        self.command = Command()
        self.sample_view_functions = [
            ViewFunction(callback=Mock(), pattern="api/test", name="test"),
        ]
        self.sample_analysis_result = AnalysisResult(
            views={"api/test": Mock()},
            admin_views=[],
            unchecked_views=[],
        )

    @patch(
        "django_access_inspector.management.commands.inspect_access_control.UrlAnalyzerService"
    )
    @patch(
        "django_access_inspector.management.commands.inspect_access_control.ViewInspectorService"
    )
    @patch(
        "django_access_inspector.management.commands.inspect_access_control.ReportGeneratorService"
    )
    @patch(
        "django_access_inspector.management.commands.inspect_access_control.SnapshotService"
    )
    def test_regular_cli_output(
        self,
        mock_snapshot_service,
        mock_report_generator,
        mock_view_inspector,
        mock_url_analyzer,
    ):
        """Test regular CLI output mode."""
        # Mock services
        mock_url_analyzer.return_value.analyze_urlconf.return_value = (
            self.sample_view_functions
        )
        mock_view_inspector.return_value.inspect_view_functions.return_value = (
            self.sample_analysis_result
        )
        mock_report_generator_instance = mock_report_generator.return_value

        # Capture stdout
        out = StringIO()

        # Call command
        call_command("inspect_access_control", stdout=out)

        # Verify service calls
        mock_url_analyzer.return_value.analyze_urlconf.assert_called_once_with(
            "ROOT_URLCONF"
        )
        mock_view_inspector.return_value.inspect_view_functions.assert_called_once_with(
            self.sample_view_functions
        )
        mock_report_generator_instance.print_terminal_report.assert_called_once()

    @patch(
        "django_access_inspector.management.commands.inspect_access_control.UrlAnalyzerService"
    )
    @patch(
        "django_access_inspector.management.commands.inspect_access_control.ViewInspectorService"
    )
    @patch(
        "django_access_inspector.management.commands.inspect_access_control.ReportGeneratorService"
    )
    @patch(
        "django_access_inspector.management.commands.inspect_access_control.SnapshotService"
    )
    def test_json_output(
        self,
        mock_snapshot_service,
        mock_report_generator,
        mock_view_inspector,
        mock_url_analyzer,
    ):
        """Test JSON output mode."""
        # Mock services
        mock_url_analyzer.return_value.analyze_urlconf.return_value = (
            self.sample_view_functions
        )
        mock_view_inspector.return_value.inspect_view_functions.return_value = (
            self.sample_analysis_result
        )
        mock_view_inspector.return_value.split_views_by_authentication.return_value = (
            Mock()
        )
        mock_report_generator.return_value.generate_json_report_from_split_views.return_value = '{"test": "json"}'

        # Capture stdout
        out = StringIO()

        # Call command
        call_command("inspect_access_control", "--output=json", stdout=out)

        # Verify JSON generation was called
        mock_report_generator.return_value.generate_json_report_from_split_views.assert_called_once()

        # Verify JSON output
        output = out.getvalue()
        assert '{"test": "json"}' in output

    @patch(
        "django_access_inspector.management.commands.inspect_access_control.UrlAnalyzerService"
    )
    @patch(
        "django_access_inspector.management.commands.inspect_access_control.ViewInspectorService"
    )
    @patch(
        "django_access_inspector.management.commands.inspect_access_control.ReportGeneratorService"
    )
    @patch(
        "django_access_inspector.management.commands.inspect_access_control.SnapshotService"
    )
    @patch("django_access_inspector.management.commands.inspect_access_control.sys")
    def test_snapshot_generation(
        self,
        mock_sys,
        mock_snapshot_service,
        mock_report_generator,
        mock_view_inspector,
        mock_url_analyzer,
    ):
        """Test snapshot generation mode."""
        # Mock services
        mock_url_analyzer.return_value.analyze_urlconf.return_value = (
            self.sample_view_functions
        )
        mock_view_inspector.return_value.inspect_view_functions.return_value = (
            self.sample_analysis_result
        )
        mock_snapshot_service_instance = mock_snapshot_service.return_value

        # Capture stdout
        out = StringIO()

        # Call command
        call_command("inspect_access_control", "--snapshot=snapshot.json", stdout=out)

        # Verify snapshot save was called
        mock_snapshot_service_instance.save_snapshot.assert_called_once_with(
            self.sample_analysis_result, "snapshot.json"
        )

        # Verify success message
        output = out.getvalue()
        assert "Snapshot saved to snapshot.json" in output

        # Verify no exit was called
        mock_sys.exit.assert_not_called()

    @patch(
        "django_access_inspector.management.commands.inspect_access_control.UrlAnalyzerService"
    )
    @patch(
        "django_access_inspector.management.commands.inspect_access_control.ViewInspectorService"
    )
    @patch(
        "django_access_inspector.management.commands.inspect_access_control.ReportGeneratorService"
    )
    @patch(
        "django_access_inspector.management.commands.inspect_access_control.SnapshotService"
    )
    @patch("django_access_inspector.management.commands.inspect_access_control.sys")
    def test_snapshot_generation_error(
        self,
        mock_sys,
        mock_snapshot_service,
        mock_report_generator,
        mock_view_inspector,
        mock_url_analyzer,
    ):
        """Test snapshot generation with error."""
        # Mock services
        mock_url_analyzer.return_value.analyze_urlconf.return_value = (
            self.sample_view_functions
        )
        mock_view_inspector.return_value.inspect_view_functions.return_value = (
            self.sample_analysis_result
        )
        mock_snapshot_service.return_value.save_snapshot.side_effect = ValueError(
            "Permission denied"
        )

        # Capture stderr
        err = StringIO()

        # Call command
        call_command("inspect_access_control", "--snapshot=snapshot.json", stderr=err)

        # Verify error message
        error_output = err.getvalue()
        assert "Failed to save snapshot: Permission denied" in error_output

        # Verify exit with code 1
        mock_sys.exit.assert_called_once_with(1)

    @patch(
        "django_access_inspector.management.commands.inspect_access_control.UrlAnalyzerService"
    )
    @patch(
        "django_access_inspector.management.commands.inspect_access_control.ViewInspectorService"
    )
    @patch(
        "django_access_inspector.management.commands.inspect_access_control.ReportGeneratorService"
    )
    @patch(
        "django_access_inspector.management.commands.inspect_access_control.SnapshotService"
    )
    @patch("django_access_inspector.management.commands.inspect_access_control.sys")
    def test_ci_mode_success(
        self,
        mock_sys,
        mock_snapshot_service,
        mock_report_generator,
        mock_view_inspector,
        mock_url_analyzer,
    ):
        """Test CI mode with successful result."""
        # Mock services
        mock_url_analyzer.return_value.analyze_urlconf.return_value = (
            self.sample_view_functions
        )
        mock_view_inspector.return_value.inspect_view_functions.return_value = (
            self.sample_analysis_result
        )

        success_result = CIResult(success=True, message="All checks passed")
        mock_report_generator.return_value.ci_mode.return_value = success_result

        # Call command
        call_command("inspect_access_control", "--ci", "--snapshot=snapshot.json")

        # Verify CI mode was called
        mock_report_generator.return_value.ci_mode.assert_called_once_with(
            self.sample_analysis_result, "snapshot.json"
        )

        # Verify exit with code 0
        mock_sys.exit.assert_called_once_with(0)

    @patch(
        "django_access_inspector.management.commands.inspect_access_control.UrlAnalyzerService"
    )
    @patch(
        "django_access_inspector.management.commands.inspect_access_control.ViewInspectorService"
    )
    @patch(
        "django_access_inspector.management.commands.inspect_access_control.ReportGeneratorService"
    )
    @patch(
        "django_access_inspector.management.commands.inspect_access_control.SnapshotService"
    )
    @patch("django_access_inspector.management.commands.inspect_access_control.sys")
    def test_ci_mode_failure(
        self,
        mock_sys,
        mock_snapshot_service,
        mock_report_generator,
        mock_view_inspector,
        mock_url_analyzer,
    ):
        """Test CI mode with failed result."""
        # Mock services
        mock_url_analyzer.return_value.analyze_urlconf.return_value = (
            self.sample_view_functions
        )
        mock_view_inspector.return_value.inspect_view_functions.return_value = (
            self.sample_analysis_result
        )

        failure_result = CIResult(
            success=False,
            new_unauthenticated_endpoints=["api/new"],
            message="New security issues found",
        )
        mock_report_generator.return_value.ci_mode.return_value = failure_result

        # Call command
        call_command("inspect_access_control", "--ci", "--snapshot=snapshot.json")

        # Verify CI mode was called
        mock_report_generator.return_value.ci_mode.assert_called_once_with(
            self.sample_analysis_result, "snapshot.json"
        )

        # Verify exit with code 1
        mock_sys.exit.assert_called_once_with(1)

    @patch("django_access_inspector.management.commands.inspect_access_control.sys")
    def test_ci_mode_without_snapshot(self, mock_sys):
        """Test CI mode without snapshot argument."""
        # Capture stderr
        err = StringIO()

        # Call command
        call_command("inspect_access_control", "--ci", stderr=err)

        # Verify error message
        error_output = err.getvalue()
        assert "CI mode requires --snapshot argument" in error_output

        # Verify exit with code 1
        mock_sys.exit.assert_called_once_with(1)

    def test_add_arguments(self):
        """Test that command arguments are properly added."""
        from argparse import ArgumentParser

        parser = ArgumentParser()
        self.command.add_arguments(parser)

        # Parse test arguments
        args = parser.parse_args(["--output=json", "--ci", "--snapshot=test.json"])

        assert args.output == "json"
        assert args.ci is True
        assert args.snapshot_path == "test.json"

    def test_add_arguments_defaults(self):
        """Test command argument defaults."""
        from argparse import ArgumentParser

        parser = ArgumentParser()
        self.command.add_arguments(parser)

        # Parse with no arguments
        args = parser.parse_args([])

        assert args.output == "cli"
        assert args.ci is False
        assert args.snapshot_path is None

    @patch(
        "django_access_inspector.management.commands.inspect_access_control.UrlAnalyzerService"
    )
    @patch(
        "django_access_inspector.management.commands.inspect_access_control.ViewInspectorService"
    )
    @patch(
        "django_access_inspector.management.commands.inspect_access_control.ReportGeneratorService"
    )
    @patch(
        "django_access_inspector.management.commands.inspect_access_control.SnapshotService"
    )
    def test_service_initialization(
        self,
        mock_snapshot_service,
        mock_report_generator,
        mock_view_inspector,
        mock_url_analyzer,
    ):
        """Test that all services are properly initialized."""
        # Mock services
        mock_url_analyzer.return_value.analyze_urlconf.return_value = []
        mock_view_inspector.return_value.inspect_view_functions.return_value = (
            AnalysisResult()
        )

        # Call command
        call_command("inspect_access_control")

        # Verify all services were instantiated
        mock_url_analyzer.assert_called_once()
        mock_view_inspector.assert_called_once()
        mock_report_generator.assert_called_once()
        mock_snapshot_service.assert_called_once()

    def test_help_text(self):
        """Test command help text."""
        assert "url matching routes" in self.command.help.lower()


class TestCommandIntegration:
    """Integration tests for command line interface."""

    @pytest.fixture
    def command_instance(self):
        """Create command instance for testing."""
        return Command()

    def test_output_choices(self, command_instance):
        """Test that output choices are correct."""
        from argparse import ArgumentParser

        parser = ArgumentParser()
        command_instance.add_arguments(parser)

        # Test valid choices
        args = parser.parse_args(["--output=cli"])
        assert args.output == "cli"

        args = parser.parse_args(["--output=json"])
        assert args.output == "json"

        # Test invalid choice should raise error
        with pytest.raises(SystemExit):
            parser.parse_args(["--output=invalid"])

    def test_ci_flag_parsing(self, command_instance):
        """Test CI flag parsing."""
        from argparse import ArgumentParser

        parser = ArgumentParser()
        command_instance.add_arguments(parser)

        # Test CI flag present
        args = parser.parse_args(["--ci"])
        assert args.ci is True

        # Test CI flag absent
        args = parser.parse_args([])
        assert args.ci is False

    def test_snapshot_path_parsing(self, command_instance):
        """Test snapshot path parsing."""
        from argparse import ArgumentParser

        parser = ArgumentParser()
        command_instance.add_arguments(parser)

        # Test with snapshot path
        args = parser.parse_args(["--snapshot", "/path/to/snapshot.json"])
        assert args.snapshot_path == "/path/to/snapshot.json"

        # Test without snapshot path
        args = parser.parse_args([])
        assert args.snapshot_path is None
