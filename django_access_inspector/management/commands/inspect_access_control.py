import logging
import sys
from argparse import RawDescriptionHelpFormatter
from typing import Any

from django.core.management.base import BaseCommand

# Import the new services
from django_access_inspector.services import (
    ReportGeneratorService,
    SnapshotService,
    UrlAnalyzerService,
    ViewInspectorService,
)
from django_access_inspector.services.debug_logger import enable_debug_logging

# Setup module logger
logger = logging.getLogger(__name__)

HELP_EPILOG = """
Examples:
  python manage.py inspect_access_control
    Run a basic access control inspection with CLI output.

  python manage.py inspect_access_control --output json
    Output the inspection results as JSON.

  python manage.py inspect_access_control --snapshot baseline.json
    Generate a snapshot of the current access control state.

  python manage.py inspect_access_control --ci --snapshot baseline.json
    Run in CI mode, comparing against a saved snapshot.

  python manage.py inspect_access_control --debug
    Enable detailed debug logging for troubleshooting.

Workflow:
  1. Run the command to inspect your project's access control.
  2. Generate a snapshot to save the current state.
  3. Use CI mode in your pipeline to detect new security issues.
  4. Use --debug to troubleshoot authentication detection.
"""


class Command(BaseCommand):
    help = (
        "Inspect and report on access control (authentication and permissions) "
        "for all URL endpoints in your Django project."
    )

    def create_parser(self, prog_name: str, subcommand: str, **kwargs: Any) -> Any:
        parser = super().create_parser(prog_name, subcommand, **kwargs)
        parser.epilog = HELP_EPILOG
        parser.formatter_class = RawDescriptionHelpFormatter
        return parser

    def add_arguments(self, parser: Any) -> None:
        super().add_arguments(parser)
        parser.add_argument(
            "--output",
            dest="output",
            choices=["cli", "json"],
            default="cli",
            help="Select report format: human-readable terminal output (`cli`) or machine-readable JSON (`json`).",
        )
        parser.add_argument(
            "--ci",
            action="store_true",
            help="Enable CI mode: fail if there are new unauthenticated or unchecked endpoints not in snapshot.",
        )
        parser.add_argument(
            "--snapshot",
            dest="snapshot_path",
            help="Path to snapshot file for CI mode or to generate new snapshot.",
        )
        parser.add_argument(
            "--debug",
            action="store_true",
            help="Enable detailed debug logging to help troubleshoot authentication detection issues.",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        try:
            self._execute(*args, **options)
        except SystemExit:
            raise
        except Exception as e:
            self.stderr.write(self.style.ERROR(f"Error: {e}"))
            self.stderr.write(
                self.style.WARNING(
                    "Run 'python manage.py inspect_access_control --help' "
                    "for usage information."
                )
            )
            sys.exit(1)

    def _execute(self, *args: Any, **options: Any) -> None:
        urlconf = "ROOT_URLCONF"

        # Enable debug logging if requested
        if options.get("debug", False):
            enable_debug_logging()
            print("🔍 Debug logging enabled - detailed analysis will be shown")

        # Initialize services
        url_analyzer = UrlAnalyzerService()
        view_inspector = ViewInspectorService()
        report_generator = ReportGeneratorService()
        snapshot_service = SnapshotService()

        # Extract views from URL patterns
        view_functions = url_analyzer.analyze_urlconf(urlconf)

        # Inspect views for permissions and authentication
        analysis_result = view_inspector.inspect_view_functions(view_functions)

        # Handle snapshot generation
        if options["snapshot_path"] and not options["ci"]:
            try:
                snapshot_service.save_snapshot(
                    analysis_result, options["snapshot_path"]
                )
                self.stdout.write(
                    self.style.SUCCESS(f"Snapshot saved to {options['snapshot_path']}")
                )
                return
            except ValueError as e:
                self.stderr.write(self.style.ERROR(f"Failed to save snapshot: {e}"))
                sys.exit(1)

        # Handle CI mode
        if options["ci"]:
            if not options["snapshot_path"]:
                self.stderr.write(
                    self.style.ERROR(
                        "CI mode requires --snapshot argument with path to snapshot file"
                    )
                )
                sys.exit(1)
                return

            ci_result = report_generator.ci_mode(
                analysis_result, options["snapshot_path"]
            )
            sys.exit(ci_result.exit_code)
            return

        # Handle regular output modes
        if options["output"] == "json":
            # Generate and output JSON report
            json_report = report_generator.generate_json_report_from_split_views(
                view_inspector.split_views_by_authentication(analysis_result.views),
                analysis_result.admin_views,
                analysis_result.unchecked_views,
            )
            self.stdout.write(json_report)
        else:
            # Generate and output terminal report
            report_generator.print_terminal_report(
                analysis_result.views,
                analysis_result.unchecked_views,
                analysis_result.admin_views,
            )
