import logging

from django.core.management.base import BaseCommand

# Import the new services
from django_access_inspector.services import (
    UrlAnalyzerService,
    ViewInspectorService,
    ReportGeneratorService,
)

# Setup module logger
logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Displays all of the url matching routes for the project."

    def add_arguments(self, parser):
        super().add_arguments(parser)
        parser.add_argument(
            "--output",
            dest="output",
            default="cli",
            help="Set the settings URL conf variable to use",
        )

    def handle(self, *args, **options):
        urlconf = "ROOT_URLCONF"

        # Initialize services
        url_analyzer = UrlAnalyzerService()
        view_inspector = ViewInspectorService()
        report_generator = ReportGeneratorService()

        # Extract views from URL patterns
        view_functions = url_analyzer.analyze_urlconf(urlconf)

        # Inspect views for permissions and authentication
        analysis_result = view_inspector.inspect_view_functions(view_functions)

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
