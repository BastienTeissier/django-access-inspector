"""
Django management command to start the MCP server for Django Access Inspector.

This command initializes and runs a FastMCP server using STDIO transport,
making the access control analysis tools available to LLM clients.
"""

import logging
import sys
from typing import Any

from django.core.management.base import BaseCommand

from django_access_inspector.mcp_server import create_mcp_server

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    """Django management command to start the MCP server."""

    help = "Start the MCP server for Django Access Inspector"

    def add_arguments(self, parser: Any) -> None:
        """Add command line arguments."""
        super().add_arguments(parser)
        parser.add_argument(
            "--debug",
            action="store_true",
            help="Enable debug logging for MCP server operations",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        """Handle the command execution."""
        try:
            # Configure logging level
            if options.get("debug", False):
                logging.basicConfig(level=logging.DEBUG)
                logger.debug("Debug logging enabled for MCP server")

            # Create and run the MCP server
            mcp_server = create_mcp_server()

            # Run with STDIO transport (default)
            logger.info("Starting Django Access Inspector MCP server...")
            mcp_server.run()

        except KeyboardInterrupt:
            logger.info("MCP server stopped by user")
            sys.exit(0)
        except Exception as e:
            logger.error(f"Failed to start MCP server: {e}")
            sys.exit(1)
