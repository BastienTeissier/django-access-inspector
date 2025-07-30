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
        version="1.0.0",
    )

    # Initialize services
    url_analyzer = UrlAnalyzerService()
    view_inspector = ViewInspectorService()

    @mcp.tool
    def analyze_endpoints(
        endpoint: Optional[str] = None,
        ctx: Optional[Context] = None,
    ) -> Dict[str, Union[str, Dict, List]]:
        """
        Analyze Django endpoints for authentication and permission configuration.

        Args:
            endpoint: Specific endpoint to analyze. If None, analyzes all endpoints.
            ctx: MCP context for logging and progress reporting

        Returns:
            Dictionary containing analysis results in JSON format
        """
        if ctx:
            ctx.info("Starting endpoint analysis...")

        try:
            # Extract views from URL patterns
            view_functions = url_analyzer.analyze_urlconf("ROOT_URLCONF")

            if ctx:
                ctx.info(f"Found {len(view_functions)} view functions")

            # Inspect views for permissions and authentication
            analysis_result = view_inspector.inspect_view_functions(view_functions)

            # If specific endpoint requested, filter results
            if endpoint:
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

            # Split views by authentication
            split_views = view_inspector.split_views_by_authentication(
                analysis_result.views
            )

            # Generate structured response
            result = {
                "summary": {
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

    @mcp.tool
    def get_endpoint_details(
        endpoint: str,
        ctx: Optional[Context] = None,
    ) -> Dict[str, Union[str, List, Dict]]:
        """
        Get detailed information about a specific endpoint.

        Args:
            endpoint: The endpoint URL pattern to analyze
            ctx: MCP context for logging and progress reporting

        Returns:
            Dictionary containing detailed endpoint information
        """
        if ctx:
            ctx.info(f"Getting detailed information for endpoint: {endpoint}")

        try:
            # Extract views from URL patterns
            view_functions = url_analyzer.analyze_urlconf("ROOT_URLCONF")

            # Find the specific endpoint
            target_view = None
            for view_func in view_functions:
                if view_func.name == endpoint or view_func.pattern == endpoint:
                    target_view = view_func
                    break

            if not target_view:
                return {
                    "error": f"Endpoint '{endpoint}' not found",
                    "available_endpoints": [
                        vf.name or vf.pattern for vf in view_functions[:10]
                    ],
                }

            # Inspect the specific view
            try:
                result = view_inspector.inspect_view_function(target_view)

                # Get additional details
                details = {
                    "endpoint": endpoint,
                    "url_name": result.url_name,
                    "url_pattern": target_view.pattern,
                    "permission_classes": result.permission_classes,
                    "authentication_classes": result.authentication_classes,
                    "view_function": {
                        "name": getattr(target_view.callback, "__name__", "unknown"),
                        "module": getattr(
                            target_view.callback, "__module__", "unknown"
                        ),
                    },
                    "security_status": "authenticated"
                    if (result.permission_classes or result.authentication_classes)
                    else "unauthenticated",
                }

                if ctx:
                    ctx.info(f"Successfully analyzed endpoint: {endpoint}")

                return details

            except ValueError as e:
                error_str = str(e)
                if error_str == "model_admin":
                    return {
                        "endpoint": endpoint,
                        "url_name": target_view.name,
                        "url_pattern": target_view.pattern,
                        "security_status": "admin_view",
                        "note": "This is a Django admin view with built-in authentication",
                    }
                elif error_str.startswith("unknown:"):
                    return {
                        "endpoint": endpoint,
                        "url_name": target_view.name,
                        "url_pattern": target_view.pattern,
                        "security_status": "unchecked",
                        "cause": error_str[8:],  # Remove "unknown:" prefix
                        "note": "This endpoint could not be analyzed for authentication patterns",
                    }
                else:
                    raise e

        except Exception as e:
            error_msg = f"Failed to get endpoint details: {str(e)}"
            logger.error(error_msg, exc_info=True)
            if ctx:
                ctx.error(error_msg)
            return {"error": error_msg}

    @mcp.prompt
    def security_analysis_prompt(
        endpoint_name: str,
        ctx: Optional[Context] = None,
    ) -> str:
        """
        Generate security analysis and recommendations for Django endpoints.

        Args:
            endpoint_name: The name of the endpoint to analyze
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
        INPUT_DATA = f"""
        <ENDPOINT_REQUEST>
        {endpoint_name}
        </ENDPOINT_REQUEST>
        """

        TASK_DESCRIPTION = """
        Rules & procedure

        Call the tool
        • If the user supplies a single endpoint slug/path, call
        analyze_endpoints("<slug>").
        • If the user supplies none, call analyze_endpoints() to scan all endpoints.

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
        logger.info(
            "MCP server created with tools: analyze_endpoints, get_endpoint_details"
        )
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
        if endpoint in unchecked.view:
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
