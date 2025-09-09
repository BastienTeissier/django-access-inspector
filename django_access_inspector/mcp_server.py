"""
MCP Server implementation for Django Access Inspector.

This module provides a FastMCP server that exposes tools for analyzing
Django endpoint authentication and permission configurations to LLM clients.
"""

import logging
from typing import Dict, List, Optional, Union

from fastmcp import FastMCP
from fastmcp.server import Context

from django_access_inspector.services import (
    SnapshotService,
    UrlAnalyzerService,
    ViewInspectorService,
)
from django_access_inspector.services.models import (
    AnalysisResult,
    ViewInspectionResult,
)

logger = logging.getLogger(__name__)


def create_mcp_server() -> FastMCP:
    """
    Create and configure the FastMCP server for Django Access Inspector.

    Returns:
        FastMCP: Configured server instance with tools and prompts
    """
    # Initialize the FastMCP server
    mcp = FastMCP(
        name="Django Access Inspector",
        version="0.4.0",
    )

    # Initialize services
    url_analyzer = UrlAnalyzerService()
    view_inspector = ViewInspectorService()
    snapshot_service = SnapshotService()

    @mcp.tool
    def analyze_endpoints(
        endpoint: str = "",
        snapshot_path: str = "",
        ctx: Optional[Context] = None,
    ) -> Dict[str, Union[str, Dict, List]]:
        """
        Analyze Django endpoints for authentication and permission configuration.

        Args:
            endpoint: Specific endpoint to analyze. If None, analyzes all endpoints.
            snapshot_path: If provided, returns only endpoints that newly fail CI
                (new unauthenticated or new unchecked) compared to the snapshot.
            ctx: MCP context for logging and progress reporting

        Returns:
            Dictionary containing analysis results in JSON format
        """
        if ctx:
            if snapshot_path:
                ctx.info(
                    "Starting CI-failing endpoints analysis (snapshot provided)..."
                )
            else:
                ctx.info("Starting endpoint analysis...")

        try:
            # Extract views from URL patterns
            view_functions = url_analyzer.analyze_urlconf("ROOT_URLCONF")

            if ctx:
                ctx.info(f"Found {len(view_functions)} view functions")

            # Inspect views for permissions and authentication
            analysis_result = view_inspector.inspect_view_functions(view_functions)

            # If specific endpoint requested, filter results
            if endpoint != "":
                if ctx:
                    ctx.info(f"Filtering results for endpoint: {endpoint}")

                filtered_result = _filter_analysis_for_endpoint(
                    analysis_result, endpoint
                )
                if not filtered_result:
                    return {
                        "error": f"Endpoint '{endpoint}' not found",
                        "suggestion": "Use analyze_endpoints() without parameters to see all available endpoints",
                    }
                analysis_result = filtered_result

            # If a snapshot is provided, return only CI-failing endpoints
            if snapshot_path != "":
                try:
                    snapshot = snapshot_service.load_snapshot(snapshot_path)
                    ci_result = snapshot_service.compare_with_snapshot(
                        analysis_result, snapshot
                    )

                    result: Dict[str, Union[str, Dict, List]] = {
                        "summary": {
                            "mode": "ci_failing",
                            "new_unauthenticated": len(
                                ci_result.new_unauthenticated_endpoints
                            ),
                            "new_unchecked": len(ci_result.new_unchecked_endpoints),
                            "removed": len(ci_result.removed_endpoints),
                            "message": ci_result.message,
                        },
                        "unauthenticated_endpoints": ci_result.new_unauthenticated_endpoints,
                        "unchecked_endpoints": [
                            {"view": uv.view, "cause": uv.cause}
                            for uv in ci_result.new_unchecked_endpoints
                        ],
                        "removed_endpoints": ci_result.removed_endpoints,
                    }

                    if endpoint:
                        result["filtered_for"] = endpoint

                    if ctx:
                        ctx.info("CI comparison completed successfully")

                    return result

                except Exception as e:
                    error_msg = f"Failed CI comparison: {str(e)}"
                    logger.error(error_msg, exc_info=True)
                    if ctx:
                        ctx.error(error_msg)
                    return {"error": error_msg}

            # Regular full analysis (no snapshot): split and return all
            split_views = view_inspector.split_views_by_authentication(
                analysis_result.views
            )

            result = {
                "summary": {
                    "mode": "full",
                    "total_views": len(analysis_result.views),
                    "authenticated_views": len(split_views.authenticated),
                    "unauthenticated_views": len(split_views.unauthenticated),
                    "unchecked_views": len(analysis_result.unchecked_views),
                    "admin_views": len(analysis_result.admin_views),
                },
                "authenticated_endpoints": _format_views_for_response(
                    split_views.authenticated
                ),
                "unauthenticated_endpoints": _format_views_for_response(
                    split_views.unauthenticated
                ),
                "unchecked_endpoints": [
                    {"view": uv.view, "cause": uv.cause}
                    for uv in analysis_result.unchecked_views
                ],
                "admin_endpoints": analysis_result.admin_views,
            }

            if endpoint:
                result["filtered_for"] = endpoint

            if ctx:
                ctx.info("Analysis completed successfully")

            return result

        except Exception as e:
            error_msg = f"Failed to analyze endpoints: {str(e)}"
            logger.error(error_msg, exc_info=True)
            if ctx:
                ctx.error(error_msg)
            return {"error": error_msg}

    @mcp.prompt
    def security_analysis_prompt(
        endpoint_name: str = "",
        snapshot_path: str = "",
        ctx: Optional[Context] = None,
    ) -> str:
        """
        Generate security analysis and recommendations for Django endpoints.

        Args:
            endpoint_name: Optional name of the endpoint to analyze
            snapshot_path: Optional path to CI snapshot for comparison
            ctx: MCP context for logging and progress reporting

        Returns:
            Formatted prompt with security analysis and recommendations
        """
        if ctx:
            ctx.info(
                f"Generating security analysis prompt for endpoint: {endpoint_name}"
            )

        TASK_CONTEXT = """
        You are a **senior Django + Django REST Framework security engineer** helping developers harden their APIs.
        Your primary tool is `analyze_endpoints`, which returns JSON metadata about one or more endpoints.
        """

        ##### Prompt element 3: Tone context #####
        TONE_CONTEXT = """
        Respond in concise, technical language aimed at experienced backend developers.
        Avoid marketing fluff; focus on actionable security guidance.
        """

        ##### Prompt element 4: Input data to process #####
        INPUT_DATA = ""
        if endpoint_name != "":
            INPUT_DATA = f"""
            <ENDPOINT_REQUEST>
            {endpoint_name}
            </ENDPOINT_REQUEST>
            """
        if snapshot_path != "":
            INPUT_DATA += f"""
            <SNAPSHOT_PATH_REQUEST>
            {snapshot_path}
            </SNAPSHOT_PATH_REQUEST>
            """

        TASK_DESCRIPTION = """
        Rules & procedure

        Call the tool
        • Single endpoint: analyze_endpoints(endpoint="<name>").
        • All endpoints: analyze_endpoints().
        • CI failing only: analyze_endpoints(snapshot_path="<snapshot.json>").
        • CI failing for a single endpoint: analyze_endpoints(endpoint="<name>", snapshot_path="<snapshot.json>").

        Analyze the code
        • Identify the file containing the endpoint and its view function.
        • Read the file to gain better understanding of the endpoint's logic.
        • Access other relevant files (models, serializers, etc.) as needed.

        Interpret results
        • Classify each endpoint's risk: critical, high, medium, low.
        • Identify missing or weak authentication / permission classes.
        • Spot dangerous HTTP methods (e.g., unauthenticated POST/PUT/DELETE).
        • If necessary, plan a remediation strategy for the endpoint.

        Generate advice
        • Recommend concrete DRF/Django fixes (decorators, mixins, settings).
        • Provide minimal working code snippets—only what is necessary.
        • Prioritize issues from highest to lowest severity.

        Output constraints
        • Follow the formatting spec
        • Do not reveal chain-of-thought.
        • If the tool returns an empty list, say “No insecure endpoints found” and stop.
        """

        IMMEDIATE_TASK = """
        Please audit the endpoint(s) listed in <ENDPOINT_REQUEST>, following the rules above,
        and deliver your findings.
        """

        PRECOGNITION = """
        Before writing your final answer:
        • Think step-by-step in an internal scratchpad.
        • Verify you have addressed every rule and produced all required sections.
        Do not include the scratchpad in the final response.
        """

        OUTPUT_FORMATTING = """
        Return your answer in exactly this Markdown structure:

        Security Assessment:
        <one-sentence overall assessment>

        Critical Issues:
        <bullet list – endpoints needing immediate attention or “None”>

        Recommendations:
        <bullet list – specific code or config changes>

        Code Examples:
        # ...concise, runnable snippets...
        Best Practices:
        <bullet list of broader advice>
        """

        PROMPT = ""

        if TASK_CONTEXT:
            PROMPT += f"""{TASK_CONTEXT}"""

        if TONE_CONTEXT:
            PROMPT += f"""\n\n{TONE_CONTEXT}"""

        if INPUT_DATA:
            PROMPT += f"""\n\n{INPUT_DATA}"""

        if TASK_DESCRIPTION:
            PROMPT += f"""\n\n{TASK_DESCRIPTION}"""

        if IMMEDIATE_TASK:
            PROMPT += f"""\n\n{IMMEDIATE_TASK}"""

        if PRECOGNITION:
            PROMPT += f"""\n\n{PRECOGNITION}"""

        if OUTPUT_FORMATTING:
            PROMPT += f"""\n\n{OUTPUT_FORMATTING}"""

        if ctx:
            ctx.info("Security analysis prompt generated successfully")

        return PROMPT

    if logger.isEnabledFor(logging.INFO):
        logger.info("MCP server created with tools: analyze_endpoints")
        logger.info("MCP server created with prompts: security_analysis_prompt")

    return mcp


def _filter_analysis_for_endpoint(
    analysis_result: AnalysisResult, endpoint: str
) -> Optional[AnalysisResult]:
    """
    Filter analysis results for a specific endpoint.

    Args:
        analysis_result: Complete analysis result
        endpoint: Endpoint name or pattern to filter for

    Returns:
        Filtered AnalysisResult or None if endpoint not found
    """
    # Check if endpoint exists in views
    if endpoint in analysis_result.views:
        return AnalysisResult(
            views={endpoint: analysis_result.views[endpoint]},
            admin_views=[],
            unchecked_views=[],
        )

    # Check in admin views
    if endpoint in analysis_result.admin_views:
        return AnalysisResult(
            views={},
            admin_views=[endpoint],
            unchecked_views=[],
        )

    # Check in unchecked views
    for unchecked in analysis_result.unchecked_views:
        if endpoint == unchecked.view or unchecked.view.endswith(f"/{endpoint}"):
            return AnalysisResult(
                views={},
                admin_views=[],
                unchecked_views=[unchecked],
            )

    return None


def _format_views_for_response(
    views: Dict[str, ViewInspectionResult],
) -> List[Dict[str, Union[str, List[str]]]]:
    """
    Format views dictionary for JSON response.

    Args:
        views: Dictionary of view inspection results

    Returns:
        List of formatted view data
    """
    return [
        {
            "endpoint": url_name,
            "permission_classes": result.permission_classes,
            "authentication_classes": result.authentication_classes,
        }
        for url_name, result in views.items()
    ]
