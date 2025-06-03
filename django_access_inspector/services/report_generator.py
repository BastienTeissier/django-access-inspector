"""
Report Generator Service for Django Access Inspector.

This service handles the generation and formatting of inspection reports
in various output formats (CLI, JSON) and provides CI mode functionality.
"""

import json
import logging
from typing import Dict, List

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .models import (
    AnalysisResult,
    CIResult,
    DefaultClasses,
    SplitViews,
    UncheckedView,
    ViewInspectionResult,
)
from .snapshot import SnapshotService

logger = logging.getLogger(__name__)


class ReportGeneratorService:
    """Service responsible for generating and formatting inspection reports."""

    # Constants
    HEADER_STYLE = "bold magenta"

    def __init__(self) -> None:
        self.console = Console()
        self.snapshot_service = SnapshotService()

    def ci_mode(self, analysis_result: AnalysisResult, snapshot_path: str) -> CIResult:
        """
        Run CI mode comparison with snapshot.

        Args:
            analysis_result: Current analysis result
            snapshot_path: Path to snapshot file

        Returns:
            CIResult with comparison details and exit code

        Raises:
            FileNotFoundError: If snapshot file doesn't exist
            ValueError: If snapshot file is invalid
        """
        try:
            snapshot = self.snapshot_service.load_snapshot(snapshot_path)
            ci_result = self.snapshot_service.compare_with_snapshot(
                analysis_result, snapshot
            )

            # Print CI results to console
            self._print_ci_results(ci_result)

            return ci_result

        except FileNotFoundError:
            error_msg = f"Snapshot file not found: {snapshot_path}"
            self._print_ci_error(
                error_msg,
                "Use --snapshot <path> to generate a baseline snapshot first.",
            )
            return CIResult(success=False, message=error_msg)
        except ValueError as e:
            error_msg = f"Invalid snapshot file: {e}"
            self._print_ci_error(error_msg)
            return CIResult(success=False, message=error_msg)

    def _print_ci_error(self, error_msg: str, additional_info: str = "") -> None:
        """Print CI error message."""
        content = f"[bold red]{error_msg}[/bold red]"
        if additional_info:
            content += f"\n{additional_info}"

        self.console.print(Panel(content, title="CI Mode Error", style="red"))

    def _print_ci_results(self, ci_result: CIResult) -> None:
        """Print CI results to console."""
        if ci_result.success:
            self._print_ci_success()
        else:
            self._print_ci_failure(ci_result)

    def _print_ci_success(self) -> None:
        """Print successful CI result."""
        self.console.print(
            Panel(
                "[bold green]✓ CI check passed[/bold green]\n"
                "No new security issues detected.",
                title="CI Mode Results",
                style="green",
            )
        )

    def _print_ci_failure(self, ci_result: CIResult) -> None:
        """Print failed CI result with details."""
        failure_details = []

        self._add_unauthenticated_details(ci_result, failure_details)
        self._add_unchecked_details(ci_result, failure_details)
        self._add_removed_details(ci_result, failure_details)

        self.console.print(
            Panel(
                "\n".join(failure_details),
                title="CI Mode Results - Security Issues Detected",
                style="red",
            )
        )

    def _add_unauthenticated_details(
        self, ci_result: CIResult, failure_details: List[str]
    ) -> None:
        """Add unauthenticated endpoint details to failure report."""
        if ci_result.new_unauthenticated_endpoints:
            count = len(ci_result.new_unauthenticated_endpoints)
            failure_details.append(
                f"[bold red]✗ {count} new unauthenticated endpoint(s):[/bold red]"
            )
            for endpoint in ci_result.new_unauthenticated_endpoints:
                failure_details.append(f"  • {endpoint}")

    def _add_unchecked_details(
        self, ci_result: CIResult, failure_details: List[str]
    ) -> None:
        """Add unchecked endpoint details to failure report."""
        if ci_result.new_unchecked_endpoints:
            count = len(ci_result.new_unchecked_endpoints)
            failure_details.append(
                f"[bold red]✗ {count} new unchecked endpoint(s):[/bold red]"
            )
            for unchecked in ci_result.new_unchecked_endpoints:
                failure_details.append(f"  • {unchecked.view} ({unchecked.cause})")

    def _add_removed_details(
        self, ci_result: CIResult, failure_details: List[str]
    ) -> None:
        """Add removed endpoint details to failure report."""
        if ci_result.removed_endpoints:
            count = len(ci_result.removed_endpoints)
            failure_details.append(
                f"[bold blue]ℹ {count} endpoint(s) removed:[/bold blue]"
            )
            for endpoint in ci_result.removed_endpoints:
                failure_details.append(f"  • {endpoint}")

    def generate_json_report_from_split_views(
        self,
        split_views: SplitViews,
        admin_views: List[str],
        unchecked_views: List[UncheckedView],
    ) -> str:
        """Generate a JSON report from SplitViews object."""
        # Convert SplitViews to the expected JSON format
        json_split_views = self._convert_split_views_to_json(split_views)

        report_data = {
            "views": json_split_views,
            "model_admin_views": admin_views,
            "unchecked_views": [
                {"view": uv.view, "cause": uv.cause} for uv in unchecked_views
            ],
        }

        return json.dumps(report_data)

    def _convert_split_views_to_json(
        self, split_views: SplitViews
    ) -> Dict[str, Dict[str, Dict[str, List[str]]]]:
        """Convert SplitViews object to JSON format."""
        authenticated = {}
        unauthenticated = {}

        for url, view_result in split_views.authenticated.items():
            authenticated[url] = {
                "permission_classes": view_result.permission_classes,
                "authentication_classes": view_result.authentication_classes,
            }

        for url, view_result in split_views.unauthenticated.items():
            unauthenticated[url] = {
                "permission_classes": view_result.permission_classes,
                "authentication_classes": view_result.authentication_classes,
            }

        return {"authenticated": authenticated, "unauthenticated": unauthenticated}

    def print_terminal_report(
        self,
        views: Dict[str, ViewInspectionResult],
        unchecked_views: List[UncheckedView],
        admin_views: List[str],
    ) -> None:
        """Print a formatted report to the terminal using Rich."""
        # Print unchecked views table
        self._print_unchecked_views_table(unchecked_views)

        # Print model admin views table
        self._print_admin_views_table(admin_views)

        # Print main views table with authentication and permission classes
        default_classes = self._get_default_classes()
        self._print_main_views_table(views, default_classes)

        # Print summary panels
        self._print_summary_panels(views, unchecked_views, admin_views, default_classes)

    def _print_unchecked_views_table(
        self, unchecked_views: List[UncheckedView]
    ) -> None:
        """Print table of unchecked views."""
        table = Table(show_header=True, header_style=self.HEADER_STYLE)
        table.add_column(f"Unchecked: {len(unchecked_views)} views")
        table.add_column("Cause")

        for view in unchecked_views:
            table.add_row(Text(view.view, style="bold red"), view.cause)

        self.console.print(table)

    def _print_admin_views_table(self, admin_views: List[str]) -> None:
        """Print table of model admin views."""
        table = Table(show_header=True, header_style=self.HEADER_STYLE)
        table.add_column(f"Model admin: {len(admin_views)} views")

        for view in admin_views:
            if view is not None:
                table.add_row(Text(view, style="bold grey"))

        self.console.print(table)

    def _print_main_views_table(
        self, views: Dict[str, ViewInspectionResult], default_classes: DefaultClasses
    ) -> None:
        """Print main table with views, authentication, and permission classes."""
        table = Table(show_header=True, header_style=self.HEADER_STYLE)
        table.add_column("Views")
        table.add_column("Authentication Classes")
        table.add_column("Permission Classes")

        for url, view_result in views.items():
            if url is not None:
                permissions = self._render_class_cell(
                    view_result.permission_classes, default_classes.permission
                )
                authentications = self._render_class_cell(
                    view_result.authentication_classes, default_classes.authentication
                )
                table.add_row(
                    Text(url, style="bold blue"), authentications, permissions
                )

        self.console.print(table)

    def _print_summary_panels(
        self,
        views: Dict[str, ViewInspectionResult],
        unchecked_views: List[UncheckedView],
        admin_views: List[str],
        default_classes: DefaultClasses,
    ) -> None:
        """Print summary panels with statistics."""
        number_of_views = len(views.keys())

        # Details panel
        self.console.print(
            Panel(
                f"Number of views: {number_of_views}\n"
                f"Unchecked views: {len(unchecked_views)}\n"
                f"Model admin views: {len(admin_views)}",
                title="Details views",
            )
        )

        # Authentication statistics
        no_authentication, authentication_default = self._count_ko_and_default(
            [view.authentication_classes for view in views.values()],
            default_classes.authentication,
        )

        self.console.print(
            Panel(
                f"Default: [{self._set_color(authentication_default)}]{authentication_default}/{number_of_views}[/{self._set_color(authentication_default)}]\n"
                f"No authentication: [{self._set_color(no_authentication)}]{no_authentication}/{number_of_views}[/{self._set_color(no_authentication)}]",
                title="Authentication",
            )
        )

        # Permission statistics
        no_permission, permission_default = self._count_ko_and_default(
            [view.permission_classes for view in views.values()],
            default_classes.permission,
        )

        self.console.print(
            Panel(
                f"Default: [{self._set_color(permission_default)}]{permission_default}/{number_of_views}[/{self._set_color(permission_default)}]\n"
                f"No permission: [{self._set_color(no_permission)}]{no_permission}/{number_of_views}[/{self._set_color(no_permission)}]",
                title="Permission",
            )
        )

    def _render_class_cell(
        self, classes: List[str], default_classes: List[str]
    ) -> Text:
        """Render a cell with class names, applying appropriate styling."""
        if len(classes) == 0:
            return Text("None", style="bold red")
        if len(classes) == 1 and classes[0] in default_classes:
            return Text(classes[0], style="bold yellow")
        return Text(", ".join(classes))

    def _count_ko_and_default(
        self, classes_list: List[List[str]], default_classes: List[str]
    ) -> tuple[int, int]:
        """Count the number of views with no classes and default classes."""
        number_of_no, number_of_default = 0, 0
        for classes in classes_list:
            if len(classes) == 0:
                number_of_no += 1
            if len(classes) == 1 and classes[0] in default_classes:
                number_of_default += 1
        return number_of_no, number_of_default

    def _set_color(self, count: int) -> str:
        """Set color based on count (green for 0, red for > 0)."""
        if count == 0:
            return "green"
        return "red"

    def _get_default_classes(self) -> DefaultClasses:
        """Get default classes from Django settings."""
        try:
            from django.conf import settings
        except ImportError:
            # Fallback for testing or non-Django environments
            return DefaultClasses(
                authentication=["BasicAuthentication"], permission=["AllowAny"]
            )

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
