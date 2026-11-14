"""
Error handling utilities for Falcon MCP Server

This module provides error handling utilities for the Falcon MCP server.
"""

from typing import Any

from .api_scopes import get_required_scopes
from .logging import get_logger

logger = get_logger(__name__)

# Common error codes and their meanings
ERROR_CODE_DESCRIPTIONS = {
    400: "Invalid request. Check your filter syntax — FQL uses + for AND, , for OR, and values must be quoted.",
    403: "Permission denied. The API credentials don't have the required access.",
    401: "Authentication failed. The API credentials are invalid or expired.",
    404: "Resource not found. The requested resource does not exist.",
    429: "Rate limit exceeded. Too many requests in a short period.",
    500: "Server error. An unexpected error occurred on the server.",
    503: "Service unavailable. The service is temporarily unavailable.",
}

# Falcon's gateway sends this in a 403 when it can't route an API for the tenant. It
# isn't an ordinary permission failure, and the raw text includes the tenant's CID.
GATEWAY_NO_ROUTE_MARKER = "proxy config not found"
GATEWAY_NO_ROUTE_DESCRIPTION = (
    "API not available to this tenant. Falcon's gateway has no route for it, which can "
    "mean the product isn't enabled or that newly added scopes haven't taken effect yet. "
    "If the scopes were just added, try again later."
)


def _has_no_gateway_route(response: dict[str, Any]) -> bool:
    """Check if a response is the gateway's 403 for an API it can't route."""
    if response.get("status_code") != 403:
        return False
    errors = response.get("body", {}).get("errors", [])
    return any(GATEWAY_NO_ROUTE_MARKER in e.get("message", "").lower() for e in errors)


def error_details(response: dict[str, Any]) -> dict[str, Any]:
    """The parts of a failed FalconPy response worth returning: status code and body.

    Response headers are left out; they add size, not diagnosis.
    """
    return {key: response[key] for key in ("status_code", "body") if key in response}


def _format_error_response(
    message: str,
    details: dict[str, Any] | None = None,
    operation: str | None = None,
) -> dict[str, Any]:
    """Format an error as a standardized response.

    Args:
        message: The error message
        details: Additional error details
        operation: The API operation that failed (used for permission errors)

    Returns:
        Dict[str, Any]: Formatted error response
    """
    response: dict[str, Any] = {"error": message}

    # Add details if provided
    if details:
        response["details"] = details

        # Special handling for permission errors (403)
        if details.get("status_code") == 403 and operation:
            required_scopes = get_required_scopes(operation)
            if required_scopes:
                response["required_scopes"] = required_scopes
                scopes_list = ", ".join(required_scopes)
                response["resolution"] = (
                    f"This operation requires the following API scopes: {scopes_list}. "
                    "Please ensure your API client has been granted these scopes in the "
                    "CrowdStrike Falcon console."
                )

    # Log the error
    logger.error("Error: %s", message)

    return response


def handle_api_response(
    response: dict[str, Any],
    operation: str,
    error_message: str = "API request failed",
    default_result: Any = None,
) -> dict[str, Any] | Any:
    """Handle an API response, returning either the result or an error.

    Args:
        response: The API response dictionary
        operation: The API operation that was performed
        error_message: The error message to use if the request failed
        default_result: The default result to return if the response is empty

    Returns:
        Dict[str, Any]|Any: The result or an error response
    """
    status_code: int | None = response.get("status_code")

    if status_code is None or status_code >= 300:
        details = error_details(response)

        if _has_no_gateway_route(response):
            # Leave out the gateway's text and body, which include the tenant's CID
            status_message = GATEWAY_NO_ROUTE_DESCRIPTION
            details = {"status_code": status_code}
        else:
            # Get a more descriptive error message based on status code
            status_message = ERROR_CODE_DESCRIPTIONS.get(
                status_code or 0, f"Request failed with status code {status_code}"
            )

            # Extract API error messages from response body
            api_errors = response.get("body", {}).get("errors", [])
            if api_errors:
                api_messages = [e.get("message", "") for e in api_errors if e.get("message")]
                if api_messages:
                    status_message += f" API said: {'; '.join(api_messages)}"

        # For permission errors, add more context
        if status_code == 403:
            required_scopes = get_required_scopes(operation)
            if required_scopes:
                status_message += f" Required scopes: {', '.join(required_scopes)}"

        # _format_error_response logs the message
        return _format_error_response(
            f"{error_message}: {status_message}", details=details, operation=operation
        )

    # Extract resources from the response body
    resources = response.get("body", {}).get("resources", [])

    if not resources and default_result is not None:
        return default_result

    return resources
