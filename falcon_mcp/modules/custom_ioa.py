"""
Custom IOA module for Falcon MCP Server.

This module provides tools for searching, creating, updating, and deleting
Custom IOA (Indicators of Attack) behavioral rules and rule groups using
Falcon Custom IOA Service Collection endpoints.
"""

import re
import unicodedata
from typing import Any

from mcp.server import FastMCP
from mcp.server.fastmcp.resources import TextResource
from mcp.types import ToolAnnotations
from pydantic import AnyUrl, Field

from falcon_mcp.common.errors import _format_error_response
from falcon_mcp.common.logging import get_logger
from falcon_mcp.common.utils import unwrap_field_default
from falcon_mcp.modules.base import BaseModule
from falcon_mcp.resources.custom_ioa import SEARCH_IOA_RULE_GROUPS_FQL_DOCUMENTATION

logger = get_logger(__name__)

# Most rules a single falcon_update_ioa_rule batch call may update.
MAX_RULE_UPDATES = 100

# Keys a `rule_updates` item may carry, with the types each value must have.
_RULE_UPDATE_FIELD_TYPES: dict[str, tuple[type, ...]] = {
    "instance_id": (str,),
    "name": (str,),
    "description": (str,),
    "enabled": (bool,),
    "pattern_severity": (str,),
    "disposition_id": (int,),
    "field_values": (list,),
}

PATTERN_SEVERITIES = ("critical", "high", "medium", "low", "informational")

_COMMENT_DOC = (
    " Control characters (including newlines and tabs) are replaced with a space "
    "and runs of whitespace are collapsed, because Falcon rejects them."
)

_WHITESPACE_RUN = re.compile(r"\s+")


def _clean_comment(comment: Any) -> str | None:
    """Return ``comment`` with control characters replaced and whitespace collapsed.

    Falcon answers HTTP 400 when a Custom IOA audit comment contains a control
    character (Unicode category Cc, which includes newline, carriage return and
    tab), so each one becomes a single space before the request is sent.
    """
    comment = unwrap_field_default(comment)
    if comment is None:
        return None
    replaced = "".join(" " if unicodedata.category(ch) == "Cc" else ch for ch in str(comment))
    return _WHITESPACE_RUN.sub(" ", replaced).strip()


class CustomIOAModule(BaseModule):
    """Module for managing Custom IOA behavioral rules and rule groups."""

    def register_tools(self, server: FastMCP) -> None:
        """Register tools with the MCP server.

        Args:
            server: MCP server instance
        """
        self._add_tool(
            server=server,
            method=self.search_ioa_rule_groups,
            name="search_ioa_rule_groups",
        )

        self._add_tool(
            server=server,
            method=self.get_ioa_platforms,
            name="get_ioa_platforms",
        )

        self._add_tool(
            server=server,
            method=self.get_ioa_rule_types,
            name="get_ioa_rule_types",
        )

        self._add_tool(
            server=server,
            method=self.create_ioa_rule_group,
            name="create_ioa_rule_group",
            annotations=ToolAnnotations(
                readOnlyHint=False,
                destructiveHint=False,
                idempotentHint=False,
                openWorldHint=True,
            ),
        )

        self._add_tool(
            server=server,
            method=self.update_ioa_rule_group,
            name="update_ioa_rule_group",
            annotations=ToolAnnotations(
                readOnlyHint=False,
                destructiveHint=True,
                idempotentHint=True,
                openWorldHint=True,
            ),
        )

        self._add_tool(
            server=server,
            method=self.delete_ioa_rule_groups,
            name="delete_ioa_rule_groups",
            annotations=ToolAnnotations(
                readOnlyHint=False,
                destructiveHint=True,
                idempotentHint=True,
                openWorldHint=True,
            ),
        )

        self._add_tool(
            server=server,
            method=self.create_ioa_rule,
            name="create_ioa_rule",
            annotations=ToolAnnotations(
                readOnlyHint=False,
                destructiveHint=False,
                idempotentHint=False,
                openWorldHint=True,
            ),
        )

        self._add_tool(
            server=server,
            method=self.update_ioa_rule,
            name="update_ioa_rule",
            annotations=ToolAnnotations(
                readOnlyHint=False,
                destructiveHint=True,
                idempotentHint=True,
                openWorldHint=True,
            ),
        )

        self._add_tool(
            server=server,
            method=self.delete_ioa_rules,
            name="delete_ioa_rules",
            annotations=ToolAnnotations(
                readOnlyHint=False,
                destructiveHint=True,
                idempotentHint=True,
                openWorldHint=True,
            ),
        )

    def register_resources(self, server: FastMCP) -> None:
        """Register resources with the MCP server.

        Args:
            server: MCP server instance
        """
        search_rule_groups_fql_resource = TextResource(
            uri=AnyUrl("falcon://custom-ioa/rule-groups/fql-guide"),
            name="falcon_search_ioa_rule_groups_fql_guide",
            description="Contains the guide for the `filter` param of the `falcon_search_ioa_rule_groups` tool.",
            text=SEARCH_IOA_RULE_GROUPS_FQL_DOCUMENTATION,
        )

        self._add_resource(
            server,
            search_rule_groups_fql_resource,
        )

    def search_ioa_rule_groups(
        self,
        filter: str | None = Field(
            default=None,
            description="FQL filter expression. See `falcon://custom-ioa/rule-groups/fql-guide` for syntax.",
            examples=["platform:'windows'+enabled:true", "rules.pattern_severity:'high'"],
        ),
        limit: int = Field(
            default=10,
            ge=1,
            le=500,
            description="Maximum number of rule groups to return. (Max: 500)",
        ),
        offset: str | None = Field(
            default=None,
            description="Starting offset for pagination. Use the offset value from a previous response.",
        ),
        sort: str | None = Field(
            default=None,
            description="Sort rule groups using FQL sort syntax. Fields: created_by, created_on, enabled, modified_by, modified_on, name, description. Example: 'modified_on.desc'",
            examples=["modified_on.desc", "name.asc"],
        ),
        q: str | None = Field(
            default=None,
            description="Free-text match query that searches across all filter string fields.",
        ),
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Search Custom IOA rule groups and return full details including their rules.

        Use this to find rule groups by platform, name, or enabled state. Consult
        falcon://custom-ioa/rule-groups/fql-guide before constructing filter expressions.
        Returns rule group objects with their contained behavioral detection rules.
        Responses include `pagination.total` (the total number of records matching the filter, or null when the API does not report a count) — use it to answer "how many" questions.
        """
        result, pagination = self._base_search_with_meta(
            operation="query_rule_groups_full",
            search_params={
                "filter": filter,
                "limit": limit,
                "offset": offset,
                "sort": sort,
                "q": q,
            },
            error_message="Failed to search IOA rule groups",
        )

        if self._is_error(result):
            return self._format_fql_error_response(
                [result], filter, SEARCH_IOA_RULE_GROUPS_FQL_DOCUMENTATION
            )

        return self._build_pagination_envelope(result or [], pagination, filter)

    def get_ioa_platforms(self) -> list[dict[str, Any]] | dict[str, Any]:
        """Get all available platforms for Custom IOA rule groups.

        Use this to discover valid platform values (windows, mac, linux) before
        creating a rule group. Returns platform details.
        """
        platform_ids = self._base_search_api_call(
            operation="query_platformsMixin0",
            search_params={},
            error_message="Failed to query IOA platforms",
        )

        if self._is_error(platform_ids):
            return [platform_ids]

        if not platform_ids:
            return []

        details = self._base_get_by_ids(
            operation="get_platformsMixin0",
            ids=platform_ids,
            use_params=True,
        )

        if self._is_error(details):
            return [details]

        # Preserve the query-step order in case the details endpoint reorders results.
        return self._reorder_by_ids(platform_ids, details, id_field="id")

    def get_ioa_rule_types(
        self,
        limit: int = Field(
            default=100,
            ge=1,
            le=500,
            description="Maximum number of rule types to return. (Max: 500)",
        ),
        offset: str | None = Field(
            default=None,
            description="Starting offset for pagination.",
        ),
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Get all available Custom IOA rule types.

        Use this to discover valid rule type IDs, required fields, and disposition IDs
        before creating a behavioral detection rule. Returns rule type details including
        platform, fields, and supported actions.
        """
        rule_type_ids = self._base_search_api_call(
            operation="query_rule_types",
            search_params={
                "limit": limit,
                "offset": offset,
            },
            error_message="Failed to query IOA rule types",
        )

        if self._is_error(rule_type_ids):
            return [rule_type_ids]

        if not rule_type_ids:
            return []

        details = self._base_get_by_ids(
            operation="get_rule_types",
            ids=rule_type_ids,
            use_params=True,
        )

        if self._is_error(details):
            return [details]

        # Preserve the query-step order in case the details endpoint reorders results.
        return self._reorder_by_ids(rule_type_ids, details, id_field="id")

    def create_ioa_rule_group(
        self,
        name: str = Field(
            description="Name for the new rule group.",
            examples=["Suspicious PowerShell Activity", "Lateral Movement Detection"],
        ),
        platform: str = Field(
            description="Platform this rule group applies to. Allowed values: windows, mac, linux.",
            examples=["windows", "mac", "linux"],
        ),
        description: str | None = Field(
            default=None,
            description="Optional description for the rule group.",
        ),
        comment: str | None = Field(
            default=None,
            description=(
                "Audit comment explaining why the rule group is being created."
                + _COMMENT_DOC
            ),
        ),
    ) -> list[dict[str, Any]]:
        """Create a new Custom IOA rule group.

        Rule groups are containers for behavioral detection rules scoped to a platform.
        Use falcon_get_ioa_platforms to see valid platform values. After creating a
        group, use falcon_create_ioa_rule to add detection rules to it.
        """
        body: dict[str, Any] = {
            "name": name,
            "platform": platform,
        }
        if description is not None:
            body["description"] = description
        comment = _clean_comment(comment)
        if comment is not None:
            body["comment"] = comment

        result = self._base_query_api_call(
            operation="create_rule_groupMixin0",
            body_params=body,
            error_message="Failed to create IOA rule group",
            default_result=[],
        )

        if self._is_error(result):
            return [result]

        return result

    def update_ioa_rule_group(
        self,
        id: str = Field(
            description="ID of the rule group to update.",
        ),
        rulegroup_version: int = Field(
            description="Current version of the rule group. Required for optimistic locking. Retrieve this from `falcon_search_ioa_rule_groups`.",
        ),
        name: str | None = Field(
            default=None,
            description="New name for the rule group.",
        ),
        description: str | None = Field(
            default=None,
            description="New description for the rule group.",
        ),
        enabled: bool | None = Field(
            default=None,
            description="Whether the rule group should be enabled or disabled.",
        ),
        comment: str | None = Field(
            default=None,
            description=(
                "Audit comment explaining why the rule group is being updated."
                + _COMMENT_DOC
            ),
        ),
    ) -> list[dict[str, Any]]:
        """Update an existing Custom IOA rule group.

        Modify name, description, or enabled state. Requires rulegroup_version for
        optimistic locking — get it from falcon_search_ioa_rule_groups.
        """
        body: dict[str, Any] = {
            "id": id,
            "rulegroup_version": rulegroup_version,
        }
        if name is not None:
            body["name"] = name
        if description is not None:
            body["description"] = description
        if enabled is not None:
            body["enabled"] = enabled
        comment = _clean_comment(comment)
        if comment is not None:
            body["comment"] = comment

        result = self._base_query_api_call(
            operation="update_rule_groupMixin0",
            body_params=body,
            error_message="Failed to update IOA rule group",
            default_result=[],
        )

        if self._is_error(result):
            return [result]

        return result

    def delete_ioa_rule_groups(
        self,
        ids: list[str] = Field(
            description="IDs of the rule groups to delete.",
        ),
        comment: str | None = Field(
            default=None,
            description=(
                "Audit comment explaining why the rule groups are being deleted."
                + _COMMENT_DOC
            ),
        ),
    ) -> list[dict[str, Any]]:
        """Delete Custom IOA rule groups by ID.

        Permanently removes the rule groups and all rules within them. Use
        falcon_search_ioa_rule_groups to find rule group IDs.
        """
        if not ids:
            return [
                _format_error_response(
                    "`ids` must be provided to delete IOA rule groups.",
                    operation="delete_rule_groupsMixin0",
                )
            ]

        result = self._base_query_api_call(
            operation="delete_rule_groupsMixin0",
            query_params={
                "ids": ids,
                "comment": _clean_comment(comment),
            },
            error_message="Failed to delete IOA rule groups",
            default_result=[],
        )

        if self._is_error(result):
            return [result]

        return result

    def create_ioa_rule(
        self,
        rulegroup_id: str = Field(
            description="ID of the rule group to add the rule to.",
        ),
        name: str = Field(
            description="Name for the new rule.",
            examples=["Block cmd.exe spawned from Office", "Detect encoded PowerShell"],
        ),
        ruletype_id: str = Field(
            description="Rule type ID that defines the detection category. Use `falcon_get_ioa_rule_types` to find valid IDs.",
        ),
        disposition_id: int = Field(
            description="Disposition ID that determines the action taken when the rule fires. Use `falcon_get_ioa_rule_types` to find valid disposition IDs for the rule type.",
        ),
        pattern_severity: str = Field(
            description="Severity level for this rule. Allowed values: critical, high, medium, low, informational.",
            examples=["critical", "high", "medium", "low", "informational"],
        ),
        field_values: list[dict[str, Any]] = Field(
            description=(
                "List of field value objects that define the rule's matching criteria. "
                "Each field value object should include: 'name' (field name), 'value' (match value), "
                "and optionally 'label', 'type', 'final_value', 'values' (list of label/value pairs). "
                "Use `falcon_get_ioa_rule_types` to discover required fields for the chosen rule type."
            ),
            examples=[
                '[{"name": "GrandparentImageFilename", "value": ".*\\\\\\\\winword\\\\.exe", "label": "Grand Parent Image Filename"}]'
            ],
        ),
        description: str | None = Field(
            default=None,
            description="Optional description for the rule.",
        ),
        comment: str | None = Field(
            default=None,
            description=(
                "Audit comment explaining why this rule is being created."
                + _COMMENT_DOC
            ),
        ),
    ) -> list[dict[str, Any]]:
        """Create a new Custom IOA behavioral detection rule within a rule group.

        Use falcon_get_ioa_rule_types first to discover rule type IDs, required fields,
        and valid disposition IDs. The field_values parameter defines the behavioral
        criteria the rule matches against (process names, file paths, command line regex).
        """
        body: dict[str, Any] = {
            "rulegroup_id": rulegroup_id,
            "name": name,
            "ruletype_id": ruletype_id,
            "disposition_id": disposition_id,
            "pattern_severity": pattern_severity,
            "field_values": field_values,
        }
        if description is not None:
            body["description"] = description
        comment = _clean_comment(comment)
        if comment is not None:
            body["comment"] = comment

        result = self._base_query_api_call(
            operation="create_rule",
            body_params=body,
            error_message="Failed to create IOA rule",
            default_result=[],
        )

        if self._is_error(result):
            return [result]

        return result

    def update_ioa_rule(
        self,
        rulegroup_id: str = Field(
            description="ID of the rule group containing the rule(s).",
        ),
        rulegroup_version: int = Field(
            description="Current version of the rule group. Required for optimistic locking. Retrieve from `falcon_search_ioa_rule_groups`.",
        ),
        instance_id: str | None = Field(
            default=None,
            description=(
                "Instance ID of the rule to update (single mode). Retrieve from "
                "`falcon_search_ioa_rule_groups`. Give either this or `rule_updates`, not both."
            ),
        ),
        name: str | None = Field(
            default=None,
            description="New name for the rule (single mode).",
        ),
        description: str | None = Field(
            default=None,
            description="New description for the rule (single mode).",
        ),
        enabled: bool | None = Field(
            default=None,
            description="Whether the rule should be enabled or disabled (single mode).",
        ),
        pattern_severity: str | None = Field(
            default=None,
            description="New severity level (single mode). Allowed values: critical, high, medium, low, informational.",
        ),
        disposition_id: int | None = Field(
            default=None,
            description="New disposition ID for the action taken when the rule fires (single mode).",
        ),
        field_values: list[dict[str, Any]] | None = Field(
            default=None,
            description="Updated field value objects that define the rule's matching criteria (single mode).",
        ),
        comment: str | None = Field(
            default=None,
            description=(
                "Audit comment explaining why the rule is being updated."
                + _COMMENT_DOC
            ),
        ),
        rule_updates: list[dict[str, Any]] | None = Field(
            default=None,
            description=(
                "Batch mode: updates for several rules in the same rule group, sent in one "
                f"API call (at most {MAX_RULE_UPDATES}). Each item needs `instance_id` plus "
                "at least one of name, description, enabled, pattern_severity, "
                "disposition_id, field_values. Give either this or `instance_id`, not both, "
                "and leave the single-mode rule fields unset."
            ),
            examples=[
                '[{"instance_id": "1", "enabled": true}, {"instance_id": "2", "enabled": true}]'
            ],
        ),
    ) -> list[dict[str, Any]]:
        """Update one or more Custom IOA behavioral detection rules in a rule group.

        Requires rulegroup_version for optimistic locking. Get the current version
        and instance IDs from falcon_search_ioa_rule_groups. New rules are created
        disabled; batch mode (`rule_updates`) can enable a whole group's rules in
        one call. The rule group is read first and any field left unset keeps
        the rule's current value; a stale rulegroup_version or an unknown rule
        returns an error without changing anything. Returns the updated rule records.
        """
        instance_id = unwrap_field_default(instance_id)
        rule_updates = unwrap_field_default(rule_updates)
        single_fields = {
            "name": unwrap_field_default(name),
            "description": unwrap_field_default(description),
            "enabled": unwrap_field_default(enabled),
            "pattern_severity": unwrap_field_default(pattern_severity),
            "disposition_id": unwrap_field_default(disposition_id),
            "field_values": unwrap_field_default(field_values),
        }

        if (instance_id is None) == (rule_updates is None):
            return [
                _format_error_response(
                    "Provide exactly one of `instance_id` (update one rule) or "
                    "`rule_updates` (update several rules in one call).",
                    operation="update_rules_v2",
                )
            ]

        if rule_updates is not None:
            set_fields = sorted(key for key, value in single_fields.items() if value is not None)
            if set_fields:
                return [
                    _format_error_response(
                        "With `rule_updates`, put rule fields inside each item instead of "
                        f"passing them directly: {', '.join(set_fields)}.",
                        operation="update_rules_v2",
                    )
                ]
            validated = self._validate_rule_updates(rule_updates)
            if isinstance(validated, dict):
                return [validated]
            updates = validated
        else:
            rule_update: dict[str, Any] = {"instance_id": instance_id}
            for key, value in single_fields.items():
                if value is not None:
                    rule_update[key] = value
            updates = [rule_update]

        completed = self._complete_rule_updates(rulegroup_id, rulegroup_version, updates)
        if isinstance(completed, dict):
            return [completed]

        body: dict[str, Any] = {
            "rulegroup_id": rulegroup_id,
            "rulegroup_version": rulegroup_version,
            "rule_updates": completed,
        }
        comment = _clean_comment(comment)
        if comment is not None:
            body["comment"] = comment

        result = self._base_query_api_call(
            operation="update_rules_v2",
            body_params=body,
            error_message="Failed to update IOA rule" + ("s" if rule_updates is not None else ""),
            default_result=[],
        )

        if self._is_error(result):
            return [result]

        return result

    def _complete_rule_updates(
        self,
        rulegroup_id: str,
        rulegroup_version: int,
        updates: list[dict[str, Any]],
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Fill each partial rule update with the rule's current values.

        Falcon expects every `rule_updates` item to carry the full rule, so the
        rule group is read once and any field the caller left unset is taken
        from the live rule (`description` defaults to "" when the rule has none).
        Returns the completed items, or an error dict when the read fails, the
        caller's rulegroup_version is stale, or a rule is not in the group.
        """
        groups = self._base_get_by_ids(
            operation="get_rule_groupsMixin0",
            ids=[rulegroup_id],
            use_params=True,
        )
        if isinstance(groups, dict):
            return _format_error_response(
                f"Could not read rule group '{rulegroup_id}' to complete the rule "
                "updates, so nothing was changed.",
                details=groups,
                operation="get_rule_groupsMixin0",
            )
        group = next(
            (g for g in groups if isinstance(g, dict) and g.get("id") == rulegroup_id),
            None,
        )
        if group is None:
            return _format_error_response(
                f"Rule group '{rulegroup_id}' was not found, so nothing was changed. "
                "Use falcon_search_ioa_rule_groups to find a valid rulegroup_id.",
                operation="get_rule_groupsMixin0",
            )

        live_version = group.get("version")
        if live_version is not None and str(live_version) != str(rulegroup_version):
            return _format_error_response(
                f"rulegroup_version {rulegroup_version} is stale: rule group "
                f"'{rulegroup_id}' is at version {live_version}. Nothing was changed; "
                "retry with the current version.",
                operation="update_rules_v2",
            )

        rules = {
            rule.get("instance_id"): rule
            for rule in group.get("rules") or []
            if isinstance(rule, dict)
        }
        missing = [u["instance_id"] for u in updates if u["instance_id"] not in rules]
        if missing:
            return _format_error_response(
                f"Rule(s) not found in rule group '{rulegroup_id}': {', '.join(missing)}. "
                "Nothing was changed.",
                operation="update_rules_v2",
            )

        completed: list[dict[str, Any]] = []
        for update in updates:
            live = rules[update["instance_id"]]
            item: dict[str, Any] = {}
            for key in _RULE_UPDATE_FIELD_TYPES:
                if update.get(key) is not None:
                    item[key] = update[key]
                elif live.get(key) is not None:
                    item[key] = live[key]
            item.setdefault("description", "")
            item.setdefault("field_values", [])
            item["rulegroup_version"] = rulegroup_version
            completed.append(item)
        return completed

    @staticmethod
    def _validate_rule_updates(
        rule_updates: Any,
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Check batch `rule_updates` items, returning them or an error dict."""

        def error(message: str) -> dict[str, Any]:
            return _format_error_response(message, operation="update_rules_v2")

        if not isinstance(rule_updates, list) or not rule_updates:
            return error("`rule_updates` must be a non-empty list of rule update objects.")
        if len(rule_updates) > MAX_RULE_UPDATES:
            return error(
                f"`rule_updates` has {len(rule_updates)} items; the limit is "
                f"{MAX_RULE_UPDATES} per call. Split the updates into several calls, "
                "using the new rulegroup_version after each call."
            )

        seen: set[str] = set()
        cleaned: list[dict[str, Any]] = []
        for position, item in enumerate(rule_updates):
            where = f"rule_updates[{position}]"
            if not isinstance(item, dict):
                return error(f"{where} must be an object.")
            unknown = sorted(set(item) - set(_RULE_UPDATE_FIELD_TYPES))
            if unknown:
                return error(
                    f"{where} has unsupported keys: {', '.join(unknown)}. Allowed keys: "
                    f"{', '.join(_RULE_UPDATE_FIELD_TYPES)}."
                )
            item_id = item.get("instance_id")
            if not isinstance(item_id, str) or not item_id:
                return error(f"{where} needs a non-empty string `instance_id`.")
            if item_id in seen:
                return error(f"{where} repeats instance_id '{item_id}'; list each rule once.")
            seen.add(item_id)

            fields = {key: value for key, value in item.items() if value is not None}
            if len(fields) < 2:
                return error(f"{where} must change at least one field besides `instance_id`.")
            for key, value in fields.items():
                expected = _RULE_UPDATE_FIELD_TYPES[key]
                # bool is an int subclass, so reject it explicitly for disposition_id.
                if not isinstance(value, expected) or (
                    key == "disposition_id" and isinstance(value, bool)
                ):
                    return error(f"{where}.{key} must be of type {expected[0].__name__}.")
            severity = fields.get("pattern_severity")
            if severity is not None and severity not in PATTERN_SEVERITIES:
                return error(
                    f"{where}.pattern_severity '{severity}' is not valid. Allowed values: "
                    f"{', '.join(PATTERN_SEVERITIES)}."
                )
            item_field_values = fields.get("field_values")
            if item_field_values is not None and not all(
                isinstance(fv, dict) for fv in item_field_values
            ):
                return error(f"{where}.field_values must be a list of objects.")
            cleaned.append(fields)
        return cleaned

    def delete_ioa_rules(
        self,
        rule_group_id: str = Field(
            description="ID of the rule group containing the rules to delete.",
        ),
        ids: list[str] = Field(
            description="IDs of the rules to delete. Retrieve from `falcon_search_ioa_rule_groups`.",
        ),
        comment: str | None = Field(
            default=None,
            description=(
                "Audit comment explaining why the rules are being deleted."
                + _COMMENT_DOC
            ),
        ),
    ) -> list[dict[str, Any]]:
        """Delete Custom IOA behavioral detection rules from a rule group.

        Use falcon_search_ioa_rule_groups to find the rule group ID and individual
        rule instance IDs to delete.
        """
        if not ids:
            return [
                _format_error_response(
                    "`ids` must be provided to delete IOA rules.",
                    operation="delete_rules",
                )
            ]

        result = self._base_query_api_call(
            operation="delete_rules",
            query_params={
                "rule_group_id": rule_group_id,
                "ids": ids,
                "comment": _clean_comment(comment),
            },
            error_message="Failed to delete IOA rules",
            default_result=[],
        )

        if self._is_error(result):
            return [result]

        return result
