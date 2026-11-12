"""
Tests for the Exclusions module.
"""

from mcp.types import ToolAnnotations

from falcon_mcp.modules.base import READ_ONLY_ANNOTATIONS
from falcon_mcp.modules.exclusions import ExclusionsModule, _find_zero_width_assertion
from tests.modules.utils.test_modules import TestModules

DESTRUCTIVE_ANNOTATIONS = ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=True,
    idempotentHint=True,
    openWorldHint=True,
)

DESTRUCTIVE_MUTATING_ANNOTATIONS = ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=True,
    idempotentHint=False,
    openWorldHint=True,
)

# Maps exclusion_type -> (query_op, get_op, create_op, update_op, delete_op).
EXPECTED_OPS = {
    "ioa": (
        "ss_ioa_exclusions_search_v2",
        "ss_ioa_exclusions_get_v2",
        "ss_ioa_exclusions_create_v2",
        "ss_ioa_exclusions_update_v2",
        "ss_ioa_exclusions_delete_v2",
    ),
    "ml": (
        "exclusions_search_v2",
        "exclusions_get_v2",
        "exclusions_create_v2",
        "exclusions_update_v2",
        "exclusions_delete_v2",
    ),
    "sensor_visibility": (
        "querySensorVisibilityExclusionsV1",
        "getSensorVisibilityExclusionsV1",
        "createSVExclusionsV1",
        "updateSensorVisibilityExclusionsV1",
        "deleteSensorVisibilityExclusionsV1",
    ),
    "certificate": (
        "cb_exclusions_query_v1",
        "cb_exclusions_get_v1",
        "cb_exclusions_create_v1",
        "cb_exclusions_update_v1",
        "cb_exclusions_delete_v1",
    ),
}


class TestExclusionsModule(TestModules):
    """Test cases for the Exclusions module."""

    def setUp(self):
        """Set up test fixtures."""
        self.setup_module(ExclusionsModule)

    # ---- Registration ----------------------------------------------------------

    def test_register_tools(self):
        """Test registering tools with the server."""
        expected_tools = [
            "falcon_search_exclusions",
            "falcon_create_exclusion",
            "falcon_update_exclusion",
            "falcon_delete_exclusions",
            "falcon_get_certificate_details",
        ]
        self.assert_tools_registered(expected_tools)

    def test_register_resources(self):
        """Test registering resources with the server."""
        expected_resources = [
            "falcon_search_exclusions_fql_guide",
        ]
        self.assert_resources_registered(expected_resources)

    def test_tool_annotations(self):
        """Mutating tools must carry the correct annotations."""
        self.module.register_tools(self.mock_server)
        self.assert_tool_annotations("falcon_search_exclusions", READ_ONLY_ANNOTATIONS)
        self.assert_tool_annotations(
            "falcon_get_certificate_details", READ_ONLY_ANNOTATIONS
        )
        self.assert_tool_annotations(
            "falcon_create_exclusion", DESTRUCTIVE_MUTATING_ANNOTATIONS
        )
        self.assert_tool_annotations(
            "falcon_update_exclusion", DESTRUCTIVE_MUTATING_ANNOTATIONS
        )
        self.assert_tool_annotations(
            "falcon_delete_exclusions", DESTRUCTIVE_ANNOTATIONS
        )

    # ---- Search ----------------------------------------------------------------

    def _search_responses(self):
        query_response = {
            "status_code": 200,
            "body": {"resources": ["excl-1", "excl-2"]},
        }
        get_response = {
            "status_code": 200,
            "body": {
                "resources": [
                    {"id": "excl-1", "value": "/tmp/a"},
                    {"id": "excl-2", "value": "/tmp/b"},
                ]
            },
        }
        return query_response, get_response

    def test_search_exclusions_per_type(self):
        """Each type queries then gets, using the correct operation names."""
        for excl_type, ops in EXPECTED_OPS.items():
            with self.subTest(exclusion_type=excl_type):
                self.mock_client.command.reset_mock()
                self.mock_client.command.side_effect = self._search_responses()

                result = self.module.search_exclusions(
                    exclusion_type=excl_type,
                    filter="value:'/tmp/*'",
                    limit=50,
                    sort=None,
                    offset=0,
                )

                self.assertEqual(self.mock_client.command.call_count, 2)
                first_call = self.mock_client.command.call_args_list[0]
                second_call = self.mock_client.command.call_args_list[1]
                self.assertEqual(first_call[0][0], ops[0])
                self.assertEqual(second_call[0][0], ops[1])
                self.assertEqual(len(result["results"]), 2)
                self.assertEqual(result["results"][0]["id"], "excl-1")

    def test_search_exclusions_reorders_to_match_sorted_ids(self):
        """When the get step returns exclusions out of order, the result is
        reordered to match the sorted ID order from the query step (ml type)."""
        query_response = {
            "status_code": 200,
            "body": {"resources": ["excl-b", "excl-a"]},
        }
        get_response = {
            "status_code": 200,
            "body": {
                "resources": [
                    {"id": "excl-a", "value": "/tmp/a"},
                    {"id": "excl-b", "value": "/tmp/b"},
                ]
            },
        }
        self.mock_client.command.side_effect = [query_response, get_response]

        result = self.module.search_exclusions(
            exclusion_type="ml",
            filter=None,
            limit=50,
            sort="created_on.desc",
            offset=0,
        )

        self.assertEqual(len(result["results"]), 2)
        self.assertEqual(result["results"][0]["id"], "excl-b")
        self.assertEqual(result["results"][1]["id"], "excl-a")

    def test_search_invalid_type(self):
        """An invalid exclusion_type returns an error response, not a crash."""
        result = self.module.search_exclusions(
            exclusion_type="bogus",
            filter=None,
            limit=10,
            sort=None,
            offset=0,
        )
        self.assertIsInstance(result, list)
        self.assertIn("error", result[0])
        # No API call should have happened.
        self.assertEqual(self.mock_client.command.call_count, 0)

    def test_search_empty_returns_fql_guide(self):
        """Empty query results include pagination context."""
        self.mock_client.command.return_value = {
            "status_code": 200,
            "body": {"resources": []},
        }
        result = self.module.search_exclusions(
            exclusion_type="ml",
            filter="value:'nothing'",
            limit=10,
            sort=None,
            offset=0,
        )
        self.assertIsInstance(result, dict)
        self.assertEqual(result["results"], [])
        self.assertIn("pagination", result)

    def test_search_error_returns_fql_guide(self):
        """Query errors include the FQL guide context."""
        self.mock_client.command.return_value = {
            "status_code": 400,
            "body": {"errors": [{"message": "Invalid filter"}]},
        }
        result = self.module.search_exclusions(
            exclusion_type="ioa",
            filter="bad filter",
            limit=10,
            sort=None,
            offset=0,
        )
        self.assertIsInstance(result, dict)
        self.assertIn("fql_guide", result)
        self.assertIn("error", result["results"][0])

    def test_sort_normalization(self):
        """ioa/ml/sv append .desc when no direction is given; certificate passes through."""
        # ML: bare 'created_on' -> 'created_on.desc'
        self.mock_client.command.side_effect = self._search_responses()
        self.module.search_exclusions(
            exclusion_type="ml",
            filter=None,
            limit=10,
            sort="created_on",
            offset=0,
        )
        ml_call = self.mock_client.command.call_args_list[0]
        self.assertEqual(ml_call[1]["parameters"]["sort"], "created_on.desc")

        # Certificate: bare 'created_on' stays unchanged.
        self.mock_client.command.reset_mock()
        self.mock_client.command.side_effect = self._search_responses()
        self.module.search_exclusions(
            exclusion_type="certificate",
            filter=None,
            limit=10,
            sort="created_on",
            offset=0,
        )
        cert_call = self.mock_client.command.call_args_list[0]
        self.assertEqual(cert_call[1]["parameters"]["sort"], "created_on")

    def test_sort_existing_direction_preserved(self):
        """An explicit direction suffix is not doubled."""
        self.mock_client.command.side_effect = self._search_responses()
        self.module.search_exclusions(
            exclusion_type="ioa",
            filter=None,
            limit=10,
            sort="created_on.asc",
            offset=0,
        )
        call = self.mock_client.command.call_args_list[0]
        self.assertEqual(call[1]["parameters"]["sort"], "created_on.asc")

    def test_limit_clamp(self):
        """Certificate clamps limit to 100; other types keep their value."""
        self.mock_client.command.side_effect = self._search_responses()
        self.module.search_exclusions(
            exclusion_type="certificate",
            filter=None,
            limit=200,
            sort=None,
            offset=0,
        )
        call = self.mock_client.command.call_args_list[0]
        self.assertEqual(call[1]["parameters"]["limit"], 100)

    def test_fql_guide_documents_ioa_sort_caveat(self):
        """The FQL guide must warn that IOA cannot sort by created_on.

        IOA v2 rejects sort=created_on with a 400; the guide steers the agent to
        last_modified instead. This is the documentation half of that bug fix.
        """
        from falcon_mcp.resources.exclusions import (
            SEARCH_EXCLUSIONS_FQL_DOCUMENTATION,
        )

        self.assertIn("Sortable fields", SEARCH_EXCLUSIONS_FQL_DOCUMENTATION)
        self.assertIn(
            "IOA does NOT support sorting by `created_on`",
            SEARCH_EXCLUSIONS_FQL_DOCUMENTATION,
        )

    def test_fql_guide_documents_wildcard_operator(self):
        """The guide must teach the `:*` wildcard operator for value/name.

        Plain `:` is exact match (any `*` is literal); substring matching needs
        the `:*` operator (e.g. value:*'*/usr/local*'). The guide must also warn
        that unsupported fields silently return empty rather than erroring.
        """
        from falcon_mcp.resources.exclusions import (
            SEARCH_EXCLUSIONS_FQL_DOCUMENTATION,
        )

        self.assertIn("Filtering caveats", SEARCH_EXCLUSIONS_FQL_DOCUMENTATION)
        self.assertIn(
            "`:*` wildcard operator",
            SEARCH_EXCLUSIONS_FQL_DOCUMENTATION,
        )
        self.assertIn(
            "value:*'*/usr/local*'",
            SEARCH_EXCLUSIONS_FQL_DOCUMENTATION,
        )
        self.assertIn(
            "Unsupported filter fields return an empty result, not an error",
            SEARCH_EXCLUSIONS_FQL_DOCUMENTATION,
        )

    def test_fql_filter_tables_drop_nonfunctional_fields(self):
        """Filter tables must list only fields the API actually filters on.

        Several fields (e.g. IOA `created_by`, `name`, `modified_by`,
        `pattern_name`, `value`) are silently ignored by the query API — they
        return an empty result instead of a 400, so they were removed from the
        filter tables. They must not reappear.
        """
        from falcon_mcp.resources.exclusions import (
            CERTIFICATE_EXCLUSIONS_FQL_FILTERS,
            IOA_EXCLUSIONS_FQL_FILTERS,
            ML_EXCLUSIONS_FQL_FILTERS,
            SENSOR_VISIBILITY_EXCLUSIONS_FQL_FILTERS,
        )

        def field_names(filters):
            # Skip the header row ("Field", "Type", "Description").
            return {row[0] for row in filters[1:]}

        ioa_fields = field_names(IOA_EXCLUSIONS_FQL_FILTERS)
        self.assertEqual(
            ioa_fields,
            {"applied_globally", "created_on", "last_modified", "pattern_id"},
        )
        for removed in ("created_by", "name", "modified_by", "pattern_name", "value"):
            self.assertNotIn(removed, ioa_fields)

        ml_fields = field_names(ML_EXCLUSIONS_FQL_FILTERS)
        self.assertEqual(
            ml_fields,
            {"applied_globally", "created_on", "last_modified", "value"},
        )
        self.assertNotIn("created_by", ml_fields)
        self.assertNotIn("modified_by", ml_fields)

        sv_fields = field_names(SENSOR_VISIBILITY_EXCLUSIONS_FQL_FILTERS)
        self.assertEqual(
            sv_fields,
            {"applied_globally", "created_on", "last_modified", "value"},
        )
        self.assertNotIn("created_by", sv_fields)
        self.assertNotIn("modified_by", sv_fields)

        cert_fields = field_names(CERTIFICATE_EXCLUSIONS_FQL_FILTERS)
        self.assertEqual(
            cert_fields,
            {"applied_globally", "created_by", "created_on", "modified_by",
             "modified_on", "name"},
        )
        self.assertNotIn("value", cert_fields)

    # ---- Create ----------------------------------------------------------------

    def _create_response(self, entity):
        return {"status_code": 201, "body": {"resources": [entity]}}

    def _create_kwargs(self, **overrides):
        """Full create kwargs with everything None unless overridden."""
        base = dict(
            name=None,
            value=None,
            pattern_id=None,
            ifn_regex=None,
            cl_regex=None,
            parent_ifn_regex=None,
            parent_cl_regex=None,
            grandparent_ifn_regex=None,
            grandparent_cl_regex=None,
            certificate=None,
            status=None,
            excluded_from=None,
            is_descendant_process=None,
            host_groups=None,
            applied_globally=None,
            description=None,
            comment=None,
        )
        base.update(overrides)
        return base

    def test_create_ioa_wrapped_body_and_host_groups(self):
        """IOA create wraps the body and maps host_groups to the host_groups key."""
        self.mock_client.command.return_value = self._create_response(
            {"id": "ioa-1", "name": "n"}
        )
        result = self.module.create_exclusion(
            exclusion_type="ioa",
            **self._create_kwargs(
                name="my-ioa",
                pattern_id="569",
                ifn_regex="/tmp/x",
                cl_regex="/tmp/x",
                host_groups=["grp-1"],
            ),
        )
        call = self.mock_client.command.call_args_list[0]
        self.assertEqual(call[0][0], "ss_ioa_exclusions_create_v2")
        body = call[1]["body"]
        self.assertIn("exclusions", body)
        excl = body["exclusions"][0]
        self.assertEqual(excl["host_groups"], ["grp-1"])
        self.assertEqual(excl["pattern_id"], "569")
        self.assertEqual(result[0]["id"], "ioa-1")

    def test_create_ml_wrapped_body_and_groups(self):
        """ML create wraps the body and maps host_groups to the groups key."""
        self.mock_client.command.return_value = self._create_response(
            {"id": "ml-1", "value": "/tmp/a"}
        )
        self.module.create_exclusion(
            exclusion_type="ml",
            **self._create_kwargs(
                value="/tmp/a",
                excluded_from=["blocking"],
                host_groups=["grp-1"],
            ),
        )
        call = self.mock_client.command.call_args_list[0]
        self.assertEqual(call[0][0], "exclusions_create_v2")
        body = call[1]["body"]
        self.assertIn("exclusions", body)
        excl = body["exclusions"][0]
        self.assertEqual(excl["groups"], ["grp-1"])
        self.assertNotIn("host_groups", excl)

    def test_create_sv_flat_body_and_groups(self):
        """Sensor visibility create uses a flat body with the groups key."""
        self.mock_client.command.return_value = self._create_response(
            {"id": "sv-1", "value": "/tmp/a"}
        )
        self.module.create_exclusion(
            exclusion_type="sensor_visibility",
            **self._create_kwargs(value="/tmp/a", host_groups=["grp-1"]),
        )
        call = self.mock_client.command.call_args_list[0]
        self.assertEqual(call[0][0], "createSVExclusionsV1")
        body = call[1]["body"]
        self.assertNotIn("exclusions", body)
        self.assertEqual(body["value"], "/tmp/a")
        self.assertEqual(body["groups"], ["grp-1"])

    def test_create_certificate_wrapped_body_and_host_groups(self):
        """Certificate create wraps the body and maps host_groups to the host_groups key."""
        cert = {"issuer": "CN=x", "thumbprint": "abc"}
        self.mock_client.command.return_value = self._create_response(
            {"id": "cert-1", "name": "n"}
        )
        self.module.create_exclusion(
            exclusion_type="certificate",
            **self._create_kwargs(
                name="trusted",
                certificate=cert,
                status="enabled",
                host_groups=["grp-1"],
            ),
        )
        call = self.mock_client.command.call_args_list[0]
        self.assertEqual(call[0][0], "cb_exclusions_create_v1")
        body = call[1]["body"]
        self.assertIn("exclusions", body)
        excl = body["exclusions"][0]
        self.assertEqual(excl["host_groups"], ["grp-1"])
        self.assertEqual(excl["status"], "enabled")
        self.assertEqual(excl["certificate"], cert)

    # ---- Create validate-and-guide negatives -----------------------------------

    def test_create_invalid_type(self):
        """Invalid type returns an error and makes no API call."""
        result = self.module.create_exclusion(
            exclusion_type="bogus", **self._create_kwargs(value="x")
        )
        self.assertIn("error", result[0])
        self.assertEqual(self.mock_client.command.call_count, 0)

    def test_create_ml_missing_value(self):
        """ML create without value returns a guiding error, no API call."""
        result = self.module.create_exclusion(
            exclusion_type="ml", **self._create_kwargs()
        )
        self.assertIn("error", result[0])
        self.assertIn("value", result[0]["error"])
        self.assertEqual(self.mock_client.command.call_count, 0)

    def test_create_ioa_missing_pattern_id(self):
        """IOA create without pattern_id returns a guiding error, no API call."""
        result = self.module.create_exclusion(
            exclusion_type="ioa",
            **self._create_kwargs(name="n", ifn_regex="/x", cl_regex="/x"),
        )
        self.assertIn("error", result[0])
        self.assertIn("pattern_id", result[0]["error"])
        self.assertEqual(self.mock_client.command.call_count, 0)

    def test_create_ioa_both_regex_wildcard(self):
        """IOA create with ifn_regex='.*' and cl_regex='.*' is rejected."""
        result = self.module.create_exclusion(
            exclusion_type="ioa",
            **self._create_kwargs(
                name="n", pattern_id="1", ifn_regex=".*", cl_regex=".*"
            ),
        )
        self.assertIn("error", result[0])
        self.assertEqual(self.mock_client.command.call_count, 0)

    def test_create_ioa_rejects_zero_width_assertions(self):
        """IOA create rejects each zero-width regex assertion pre-flight, naming it."""
        for token in ["^", "$", r"\b", r"\B", r"\A", r"\Z"]:
            with self.subTest(token=token):
                self.mock_client.command.reset_mock()
                result = self.module.create_exclusion(
                    exclusion_type="ioa",
                    **self._create_kwargs(
                        name="n",
                        pattern_id="1",
                        ifn_regex=f"{token}foo",
                        cl_regex="/tmp/bar",
                    ),
                )
                self.assertIn("error", result[0])
                self.assertIn(token, result[0]["error"])
                self.assertIn("ifn_regex", result[0]["error"])
                self.assertEqual(self.mock_client.command.call_count, 0)

    def test_create_ioa_rejects_zero_width_in_any_regex_field(self):
        """Zero-width assertions are caught in optional IOA regex fields too."""
        for field in ["cl_regex", "parent_ifn_regex", "grandparent_cl_regex"]:
            with self.subTest(field=field):
                self.mock_client.command.reset_mock()
                kwargs = self._create_kwargs(
                    name="n", pattern_id="1", ifn_regex="/tmp/x", cl_regex="/tmp/y"
                )
                kwargs[field] = r"\bfoo"
                result = self.module.create_exclusion(exclusion_type="ioa", **kwargs)
                self.assertIn("error", result[0])
                self.assertIn(field, result[0]["error"])
                self.assertEqual(self.mock_client.command.call_count, 0)

    def test_create_ioa_valid_regex_passes(self):
        """A valid IOA regex with no zero-width assertion reaches the API unchanged."""
        self.mock_client.command.return_value = self._create_response(
            {"id": "ioa-1", "name": "n"}
        )
        result = self.module.create_exclusion(
            exclusion_type="ioa",
            **self._create_kwargs(
                name="n",
                pattern_id="1",
                ifn_regex="/usr/bin/foo",
                cl_regex="--flag value",
            ),
        )
        call = self.mock_client.command.call_args_list[0]
        self.assertEqual(call[0][0], "ss_ioa_exclusions_create_v2")
        self.assertEqual(
            call[1]["body"]["exclusions"][0]["ifn_regex"], "/usr/bin/foo"
        )
        self.assertEqual(result[0]["id"], "ioa-1")

    def test_create_ioa_escaped_and_char_class_tokens_pass(self):
        """Escaped ^/$ and char-class contexts are literals, not assertions."""
        self.mock_client.command.return_value = self._create_response(
            {"id": "ioa-1", "name": "n"}
        )
        result = self.module.create_exclusion(
            exclusion_type="ioa",
            **self._create_kwargs(
                name="n",
                pattern_id="1",
                ifn_regex=r"/tmp/\$cache",
                cl_regex=r"[$^]value",
            ),
        )
        self.assertEqual(self.mock_client.command.call_count, 1)
        self.assertEqual(result[0]["id"], "ioa-1")

    def test_create_ioa_leading_bracket_class_member_passes(self):
        """A ] as the first class member is a literal, so the class still absorbs
        following ^/$ tokens (e.g. `[]^]`) rather than false-flagging them."""
        self.mock_client.command.return_value = self._create_response(
            {"id": "ioa-1", "name": "n"}
        )
        result = self.module.create_exclusion(
            exclusion_type="ioa",
            **self._create_kwargs(
                name="n",
                pattern_id="1",
                ifn_regex="/bin/foo[]^]",
                cl_regex="[^]$]bar",
            ),
        )
        self.assertEqual(self.mock_client.command.call_count, 1)
        self.assertEqual(result[0]["id"], "ioa-1")

    def test_find_zero_width_assertion_non_word_boundary(self):
        """\\B is flagged, but an escaped backslash followed by B is a literal."""
        self.assertEqual(_find_zero_width_assertion(r"foo\Bbar"), r"\B")
        self.assertIsNone(_find_zero_width_assertion(r"C:\\Bin\\app\.exe"))
        self.assertIsNone(_find_zero_width_assertion(r"[\B]"))

    def test_create_ioa_escaped_backslash_before_b_passes(self):
        """`\\\\B` (literal backslash then B) is not a zero-width assertion."""
        self.mock_client.command.return_value = self._create_response({"id": "ioa-1"})
        result = self.module.create_exclusion(
            exclusion_type="ioa",
            **self._create_kwargs(
                name="n", pattern_id="1", ifn_regex=r".*\\Bin\\app\.exe", cl_regex="/x"
            ),
        )
        self.assertEqual(self.mock_client.command.call_count, 1)
        self.assertEqual(result[0]["id"], "ioa-1")

    def test_create_ioa_cl_regex_defaults_to_match_all(self):
        """An unset or empty cl_regex defaults to '.*' on create."""
        for cl_regex in (None, ""):
            with self.subTest(cl_regex=cl_regex):
                self.mock_client.command.reset_mock()
                self.mock_client.command.return_value = self._create_response({"id": "ioa-1"})
                result = self.module.create_exclusion(
                    exclusion_type="ioa",
                    **self._create_kwargs(
                        name="n", pattern_id="1", ifn_regex=r".*\\app\.exe", cl_regex=cl_regex
                    ),
                )
                excl = self.mock_client.command.call_args[1]["body"]["exclusions"][0]
                self.assertEqual(excl["cl_regex"], ".*")
                self.assertEqual(result[0]["id"], "ioa-1")

    def test_create_ioa_cl_regex_omitted_entirely(self):
        """Calling without the cl_regex argument at all also defaults it to '.*'."""
        self.mock_client.command.return_value = self._create_response({"id": "ioa-1"})
        kwargs = self._create_kwargs(name="n", pattern_id="1", ifn_regex=r".*\\app\.exe")
        del kwargs["cl_regex"]
        self.module.create_exclusion(exclusion_type="ioa", **kwargs)
        excl = self.mock_client.command.call_args[1]["body"]["exclusions"][0]
        self.assertEqual(excl["cl_regex"], ".*")

    def test_create_ioa_match_all_ifn_with_default_cl_rejected(self):
        """ifn_regex '.*' with the defaulted cl_regex is still rejected."""
        result = self.module.create_exclusion(
            exclusion_type="ioa",
            **self._create_kwargs(name="n", pattern_id="1", ifn_regex=".*", cl_regex=None),
        )
        self.assertIn("error", result[0])
        self.assertEqual(self.mock_client.command.call_count, 0)

    def test_update_ioa_still_requires_cl_regex(self):
        """The cl_regex default applies to create only."""
        result = self.module.update_exclusion(
            exclusion_type="ioa",
            id="ioa-1",
            **self._create_kwargs(name="n", pattern_id="1", ifn_regex="/x", cl_regex=None),
        )
        self.assertIn("error", result[0])
        self.assertIn("cl_regex", result[0]["error"])
        self.assertEqual(self.mock_client.command.call_count, 0)

    def test_create_ml_rejects_invalid_excluded_from(self):
        """excluded_from must be a subset of {'blocking', 'extraction'}."""
        for excluded_from in (["blocking", "scanning"], ["Blocking"], [""]):
            with self.subTest(excluded_from=excluded_from):
                result = self.module.create_exclusion(
                    exclusion_type="ml",
                    **self._create_kwargs(value="/tmp/a", excluded_from=excluded_from),
                )
                self.assertIn("error", result[0])
                self.assertIn("blocking, extraction", result[0]["error"])
                self.assertEqual(self.mock_client.command.call_count, 0)

    def test_create_ml_accepts_valid_excluded_from(self):
        """Both allowed excluded_from values reach the API."""
        self.mock_client.command.return_value = self._create_response({"id": "ml-1"})
        self.module.create_exclusion(
            exclusion_type="ml",
            **self._create_kwargs(value="/tmp/a", excluded_from=["blocking", "extraction"]),
        )
        excl = self.mock_client.command.call_args[1]["body"]["exclusions"][0]
        self.assertEqual(excl["excluded_from"], ["blocking", "extraction"])

    # ---- Duplicate guard ---------------------------------------------------------

    def _ok(self, resources, total=None):
        body = {"resources": resources}
        if total is not None:
            body["meta"] = {"pagination": {"total": total, "offset": 0, "limit": 500}}
        return {"status_code": 200, "body": body}

    def test_create_ioa_skip_if_duplicate_returns_existing(self):
        """An IOA exclusion with the same pattern and regexes is returned, not created."""
        existing = {
            "id": "ioa-old",
            "pattern_id": "569",
            "ifn_regex": "/tmp/x",
            "cl_regex": ".*",
        }
        other = {**existing, "id": "ioa-other", "ifn_regex": "/tmp/y"}
        self.mock_client.command.side_effect = [
            self._ok(["ioa-other", "ioa-old"], total=2),
            self._ok([other, existing]),
        ]
        result = self.module.create_exclusion(
            exclusion_type="ioa",
            skip_if_duplicate=True,
            **self._create_kwargs(name="n", pattern_id="569", ifn_regex="/tmp/x"),
        )
        self.assertEqual(result[0]["id"], "ioa-old")
        self.assertTrue(result[0]["skipped_duplicate"])
        self.assertIn("note", result[0])
        ops = [c[0][0] for c in self.mock_client.command.call_args_list]
        self.assertEqual(ops, ["ss_ioa_exclusions_search_v2", "ss_ioa_exclusions_get_v2"])
        params = self.mock_client.command.call_args_list[0][1]["parameters"]
        self.assertEqual(params["filter"], "pattern_id:'569'")

    def test_create_ioa_skip_if_duplicate_creates_when_regex_differs(self):
        """Same pattern but different cl_regex is not a duplicate."""
        existing = {"id": "ioa-old", "pattern_id": "569", "ifn_regex": "/tmp/x", "cl_regex": ".*"}
        self.mock_client.command.side_effect = [
            self._ok(["ioa-old"], total=1),
            self._ok([existing]),
            self._create_response({"id": "ioa-new"}),
        ]
        result = self.module.create_exclusion(
            exclusion_type="ioa",
            skip_if_duplicate=True,
            **self._create_kwargs(
                name="n", pattern_id="569", ifn_regex="/tmp/x", cl_regex="--run"
            ),
        )
        self.assertEqual(result[0]["id"], "ioa-new")
        self.assertEqual(
            self.mock_client.command.call_args_list[-1][0][0], "ss_ioa_exclusions_create_v2"
        )

    def test_create_skip_if_duplicate_no_matches_creates(self):
        """No search hits means the exclusion is created."""
        self.mock_client.command.side_effect = [
            self._ok([], total=0),
            self._create_response({"id": "ml-new"}),
        ]
        result = self.module.create_exclusion(
            exclusion_type="ml",
            skip_if_duplicate=True,
            **self._create_kwargs(value="C:\\Tools\\it's.exe"),
        )
        self.assertEqual(result[0]["id"], "ml-new")
        params = self.mock_client.command.call_args_list[0][1]["parameters"]
        self.assertEqual(params["filter"], "value:'C:\\\\Tools\\\\it\\'s.exe'")
        self.assertEqual(self.mock_client.command.call_args_list[0][0][0], "exclusions_search_v2")

    def test_create_ml_skip_if_duplicate_returns_existing(self):
        """An ML exclusion with the same value is returned, not created."""
        self.mock_client.command.side_effect = [
            self._ok(["ml-old"], total=1),
            self._ok([{"id": "ml-old", "value": "/tmp/a"}]),
        ]
        result = self.module.create_exclusion(
            exclusion_type="ml",
            skip_if_duplicate=True,
            **self._create_kwargs(value="/tmp/a"),
        )
        self.assertEqual(result[0]["id"], "ml-old")
        self.assertTrue(result[0]["skipped_duplicate"])
        self.assertEqual(self.mock_client.command.call_count, 2)

    def test_create_skip_if_duplicate_pages_through_results(self):
        """The duplicate scan follows offsets until the total is reached."""
        first_ids = [f"ml-{i}" for i in range(500)]
        self.mock_client.command.side_effect = [
            self._ok(first_ids, total=501),
            self._ok([{"id": i, "value": "/other"} for i in first_ids]),
            self._ok(["ml-last"], total=501),
            self._ok([{"id": "ml-last", "value": "/tmp/a"}]),
        ]
        result = self.module.create_exclusion(
            exclusion_type="ml",
            skip_if_duplicate=True,
            **self._create_kwargs(value="/tmp/a"),
        )
        self.assertEqual(result[0]["id"], "ml-last")
        second_search = self.mock_client.command.call_args_list[2][1]["parameters"]
        self.assertEqual(second_search["offset"], 500)

    def test_create_skip_if_duplicate_search_error_blocks_create(self):
        """A failed duplicate search returns the error instead of creating."""
        self.mock_client.command.side_effect = [
            {"status_code": 403, "body": {"errors": [{"code": 403, "message": "denied"}]}},
        ]
        result = self.module.create_exclusion(
            exclusion_type="ml",
            skip_if_duplicate=True,
            **self._create_kwargs(value="/tmp/a"),
        )
        self.assertIn("error", result[0])
        self.assertEqual(self.mock_client.command.call_count, 1)

    def test_create_skip_if_duplicate_get_error_blocks_create(self):
        """A failed detail fetch during the duplicate scan returns the error."""
        self.mock_client.command.side_effect = [
            self._ok(["ml-old"], total=1),
            {"status_code": 500, "body": {"errors": [{"code": 500, "message": "boom"}]}},
        ]
        result = self.module.create_exclusion(
            exclusion_type="ml",
            skip_if_duplicate=True,
            **self._create_kwargs(value="/tmp/a"),
        )
        self.assertIn("error", result[0])
        self.assertEqual(self.mock_client.command.call_count, 2)

    def test_create_skip_if_duplicate_ignored_for_other_types(self):
        """skip_if_duplicate does not search for sensor_visibility or certificate."""
        self.mock_client.command.return_value = self._create_response({"id": "sv-1"})
        self.module.create_exclusion(
            exclusion_type="sensor_visibility",
            skip_if_duplicate=True,
            **self._create_kwargs(value="/tmp/a", host_groups=["grp-1"]),
        )
        self.assertEqual(self.mock_client.command.call_count, 1)
        self.assertEqual(
            self.mock_client.command.call_args[0][0], "createSVExclusionsV1"
        )

    def test_create_skip_if_duplicate_validates_before_searching(self):
        """Body validation errors are returned before any duplicate search."""
        result = self.module.create_exclusion(
            exclusion_type="ml",
            skip_if_duplicate=True,
            **self._create_kwargs(value=None),
        )
        self.assertIn("error", result[0])
        self.assertEqual(self.mock_client.command.call_count, 0)

    def test_create_ml_value_with_caret_unaffected(self):
        """Non-IOA types are not subject to the IOA regex assertion check."""
        self.mock_client.command.return_value = self._create_response(
            {"id": "ml-1", "value": "^weird$"}
        )
        result = self.module.create_exclusion(
            exclusion_type="ml",
            **self._create_kwargs(value="^weird$", host_groups=["grp-1"]),
        )
        self.assertEqual(self.mock_client.command.call_count, 1)
        self.assertEqual(result[0]["id"], "ml-1")

    def test_update_ioa_rejects_zero_width_assertion(self):
        """IOA update shares the builder, so it also rejects assertions pre-flight."""
        result = self.module.update_exclusion(
            exclusion_type="ioa",
            id="ioa-1",
            **self._create_kwargs(
                name="n", pattern_id="1", ifn_regex="^foo", cl_regex="/tmp/y"
            ),
        )
        self.assertIn("error", result[0])
        self.assertIn("^", result[0]["error"])
        self.assertEqual(self.mock_client.command.call_count, 0)

    def test_create_sv_empty_host_groups(self):
        """Sensor visibility create with no host_groups returns a guiding error."""
        result = self.module.create_exclusion(
            exclusion_type="sensor_visibility",
            **self._create_kwargs(value="/tmp/a"),
        )
        self.assertIn("error", result[0])
        self.assertIn("host_groups", result[0]["error"])
        self.assertEqual(self.mock_client.command.call_count, 0)

    def test_create_certificate_bad_status(self):
        """Certificate create with an invalid status is rejected."""
        result = self.module.create_exclusion(
            exclusion_type="certificate",
            **self._create_kwargs(
                name="n", certificate={"thumbprint": "x"}, status="bad"
            ),
        )
        self.assertIn("error", result[0])
        self.assertIn("status", result[0]["error"])
        self.assertEqual(self.mock_client.command.call_count, 0)

    # ---- Update ----------------------------------------------------------------

    def test_update_missing_id(self):
        """Update without an id returns a guiding error."""
        result = self.module.update_exclusion(
            exclusion_type="ml", id=None, **self._create_kwargs(value="/tmp/a")
        )
        self.assertIn("error", result[0])
        self.assertEqual(self.mock_client.command.call_count, 0)

    def test_update_invalid_type(self):
        """Update with an invalid type returns an error."""
        result = self.module.update_exclusion(
            exclusion_type="bogus", id="x", **self._create_kwargs(value="/tmp/a")
        )
        self.assertIn("error", result[0])
        self.assertEqual(self.mock_client.command.call_count, 0)

    def test_update_flat_type_id_top_level(self):
        """Sensor visibility update places id at the top level of the flat body."""
        self.mock_client.command.return_value = self._create_response(
            {"id": "sv-1", "value": "/tmp/a"}
        )
        self.module.update_exclusion(
            exclusion_type="sensor_visibility",
            id="sv-1",
            **self._create_kwargs(value="/tmp/a", host_groups=["grp-1"]),
        )
        call = self.mock_client.command.call_args_list[0]
        self.assertEqual(call[0][0], "updateSensorVisibilityExclusionsV1")
        body = call[1]["body"]
        self.assertEqual(body["id"], "sv-1")
        self.assertNotIn("exclusions", body)

    def test_update_wrapped_type_id_inside_object(self):
        """IOA/ML/certificate updates put id inside the exclusions object."""
        self.mock_client.command.return_value = self._create_response(
            {"id": "ioa-1", "name": "n"}
        )
        self.module.update_exclusion(
            exclusion_type="ioa",
            id="ioa-1",
            **self._create_kwargs(
                name="n",
                pattern_id="569",
                ifn_regex="/x",
                cl_regex="/x",
            ),
        )
        call = self.mock_client.command.call_args_list[0]
        self.assertEqual(call[0][0], "ss_ioa_exclusions_update_v2")
        body = call[1]["body"]
        self.assertEqual(body["exclusions"][0]["id"], "ioa-1")

    # ---- Delete ----------------------------------------------------------------

    def test_delete_per_type(self):
        """Delete uses the right op name and passes ids as query params."""
        for excl_type, ops in EXPECTED_OPS.items():
            with self.subTest(exclusion_type=excl_type):
                self.mock_client.command.reset_mock()
                self.mock_client.command.return_value = {
                    "status_code": 200,
                    "body": {"resources": [{"id": "x"}]},
                }
                self.module.delete_exclusions(
                    exclusion_type=excl_type, ids=["x", "y"], comment="cleanup"
                )
                call = self.mock_client.command.call_args_list[0]
                self.assertEqual(call[0][0], ops[4])
                self.assertEqual(call[1]["parameters"]["ids"], ["x", "y"])

    def test_delete_empty_ids(self):
        """Delete with no ids returns a guiding error."""
        result = self.module.delete_exclusions(
            exclusion_type="ml", ids=None, comment=None
        )
        self.assertIn("error", result[0])
        self.assertEqual(self.mock_client.command.call_count, 0)

    def test_delete_invalid_type(self):
        """Delete with an invalid type returns an error."""
        result = self.module.delete_exclusions(
            exclusion_type="bogus", ids=["x"], comment=None
        )
        self.assertIn("error", result[0])
        self.assertEqual(self.mock_client.command.call_count, 0)

    # ---- Certificate discovery -------------------------------------------------

    def test_get_certificate_details(self):
        """get_certificate_details calls certificates_get_v1 with the sha256."""
        self.mock_client.command.return_value = {
            "status_code": 200,
            "body": {"resources": [{"id": "abc", "certificate": {}}]},
        }
        result = self.module.get_certificate_details(sha256="abc123")
        call = self.mock_client.command.call_args_list[0]
        self.assertEqual(call[0][0], "certificates_get_v1")
        self.assertEqual(call[1]["parameters"]["ids"], ["abc123"])
        self.assertEqual(result[0]["id"], "abc")
