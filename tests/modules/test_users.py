"""
Tests for the Users module.
"""

import asyncio
import unittest
from unittest.mock import AsyncMock

from mcp.types import ToolAnnotations

from falcon_mcp.modules.users import UsersModule
from tests.modules.utils.test_modules import TestModules

U1 = "11111111-1111-1111-1111-111111111111"
U2 = "22222222-2222-2222-2222-222222222222"
CID = "c" * 32


def _ok(resources, total=None):
    body = {"resources": resources, "errors": []}
    if total is not None:
        body["meta"] = {"pagination": {"offset": 0, "limit": 500, "total": total}}
    return {"status_code": 200, "body": body}


def _grant(uuid, role_id):
    return {"uuid": uuid, "role_id": role_id, "role_name": role_id, "grant_type": "direct"}


class TestUsersModule(TestModules):
    """Test cases for the Users module."""

    def setUp(self):
        self.setup_module(UsersModule)

        async def _command_async(*args, **kwargs):
            return self.mock_client.command(*args, **kwargs)

        self.mock_client.command_async = AsyncMock(side_effect=_command_async)

    # --- registration ------------------------------------------------------

    def test_register_tools(self):
        self.assert_tools_registered(
            [
                "falcon_search_users",
                "falcon_get_user_roles",
                "falcon_search_roles",
                "falcon_get_role_permissions",
                "falcon_manage_user_roles",
                "falcon_reset_user_credentials",
                "falcon_create_user",
                "falcon_update_user",
                "falcon_delete_user",
            ]
        )

    def test_write_annotations(self):
        self.module.register_tools(self.mock_server)
        for name, destructive, idempotent in (
            ("falcon_manage_user_roles", True, True),
            ("falcon_reset_user_credentials", True, False),
            ("falcon_create_user", False, False),
            ("falcon_update_user", False, True),
            ("falcon_delete_user", True, True),
        ):
            with self.subTest(tool=name):
                self.assert_tool_annotations(
                    name,
                    ToolAnnotations(
                        readOnlyHint=False,
                        destructiveHint=destructive,
                        idempotentHint=idempotent,
                        openWorldHint=True,
                    ),
                )

    # --- search_users ------------------------------------------------------

    def test_search_users_hydrates_in_query_order(self):
        self.mock_client.command.side_effect = [
            _ok([U1, U2], total=2),
            _ok([{"uuid": U2, "uid": "b"}, {"uuid": U1, "uid": "a"}]),
        ]

        result = self.module.search_users(
            filter="status:'active'", user_type="internal", limit=50, offset=None, sort="uid.asc"
        )

        query, details = self.mock_client.command.call_args_list
        self.assertEqual(query[0][0], "queryUserV2")
        self.assertEqual(query[1]["parameters"]["user_type"], "internal")
        self.assertEqual(details[0][0], "retrieveUsersGETV2")
        self.assertEqual(details[1]["body"], {"ids": [U1, U2]})
        self.assertEqual([u["uuid"] for u in result["results"]], [U1, U2])
        self.assertEqual(result["pagination"]["total"], 2)

    def test_search_users_rejects_bad_user_type(self):
        result = self.module.search_users(
            filter=None, user_type="partner", limit=50, offset=None, sort=None
        )
        self.assertIn("error", result)
        self.mock_client.command.assert_not_called()

    # --- get_user_roles ------------------------------------------------------

    def _roles(self, **kwargs):
        args = {"user_uuids": None, "role_ids": None, "direct_only": False}
        return asyncio.run(self.module.get_user_roles(**{**args, **kwargs}))

    def test_roles_for_given_users_with_unknown_one(self):
        unknown = "33333333-3333-3333-3333-333333333333"

        def route(op, **kwargs):
            uuid = kwargs["parameters"]["user_uuid"]
            if uuid == unknown:
                return {
                    "status_code": 400,
                    "body": {"errors": [{"message": f"invalid user uuid='{uuid}' specified"}]},
                }
            return _ok([_grant(uuid, "falconhost_admin"), _grant(uuid, "workflow_executor")])

        self.mock_client.command.side_effect = route

        result = self._roles(user_uuids=[U1.upper(), unknown], direct_only=True)

        self.assertEqual([r["uuid"] for r in result["results"]], [U1])
        self.assertEqual(len(result["results"][0]["grants"]), 2)
        self.assertEqual(result["not_found"], [unknown])
        self.assertNotIn("holders", result)
        params = self.mock_client.command.call_args_list[0][1]["parameters"]
        self.assertTrue(params["direct_only"])

    def test_who_holds_a_role_checks_every_user(self):
        def route(op, **kwargs):
            if op == "queryUserV2":
                return _ok([U1, U2], total=2)
            uuid = kwargs["parameters"]["user_uuid"]
            roles = ["falconhost_admin"] if uuid == U2 else ["falconhost_read_only"]
            return _ok([_grant(uuid, r) for r in roles])

        self.mock_client.command.side_effect = route

        result = self._roles(role_ids=["falconhost_admin"])

        self.assertEqual(result["holders"], [U2])
        self.assertEqual([r["uuid"] for r in result["results"]], [U2])
        self.assertEqual(result["users_checked"], 2)
        self.assertNotIn("warning", result)

    def test_scan_warns_when_the_tenant_has_more_users(self):
        self.mock_client.command.side_effect = lambda op, **kw: (
            _ok([U1], total=900) if op == "queryUserV2" else _ok([])
        )

        result = self._roles()

        self.assertIn("warning", result)

    def test_role_lookup_failure_is_reported(self):
        self.mock_client.command.return_value = {
            "status_code": 403,
            "body": {"errors": [{"message": "access denied"}]},
        }

        result = self._roles(user_uuids=[U1])

        self.assertIn("error", result)
        self.assertEqual(result["required_scopes"], ["User Management:read"])

    def test_role_inputs_are_validated(self):
        for kwargs in (
            {"user_uuids": ["not-a-uuid"]},
            {"role_ids": ["bad role'"]},
            {"user_uuids": [f"{i:08d}-0000-0000-0000-000000000000" for i in range(101)]},
        ):
            with self.subTest(kwargs=str(kwargs)[:40]):
                self.mock_client.command.reset_mock()
                self.assertIn("error", self._roles(**kwargs))
                self.mock_client.command.assert_not_called()

    # --- search_roles / get_role_permissions ---------------------------------

    def test_search_roles_filters_and_sorts(self):
        self.mock_client.command.side_effect = [
            _ok(["falconhost_admin", "abc123", "remote_responder_three"]),
            _ok(
                [
                    {"id": "remote_responder_three", "display_name": "Real Time Responder - Administrator", "type": "default"},
                    {"id": "abc123", "display_name": "Custom Admin", "type": "custom"},
                    {"id": "falconhost_admin", "display_name": "Falcon Administrator", "type": "default"},
                ]
            ),
        ]

        result = self.module.search_roles(name_contains="ADMIN", role_type="default")

        self.assertEqual(
            [r["id"] for r in result["results"]], ["falconhost_admin", "remote_responder_three"]
        )
        self.assertEqual(result["total"], 2)

    def test_role_permissions_filter_and_cap(self):
        perms = [f"rtr_perm_{i}" for i in range(600)] + ["user_read"]
        self.mock_client.command.return_value = _ok(perms)

        result = self.module.get_role_permissions(
            role_id="falconhost_admin", contains="RTR", include_details=False
        )

        self.assertEqual(result["total"], 601)
        self.assertEqual(result["matched"], 600)
        self.assertEqual(len(result["permissions"]), 500)
        self.assertTrue(result["truncated"])

    def test_role_permissions_with_details(self):
        self.mock_client.command.side_effect = [
            _ok(["user_read", "rtr_get"]),
            _ok([{"id": "user_read", "display_name": "Read users"}]),
        ]

        result = self.module.get_role_permissions(
            role_id="falconhost_admin", contains="user", include_details=True
        )

        details_call = self.mock_client.command.call_args_list[1]
        self.assertEqual(details_call[0][0], "entitiesPermissionsGETV1")
        self.assertEqual(details_call[1]["body"], {"ids": ["user_read"]})
        self.assertEqual(result["permissions"][0]["display_name"], "Read users")

    def test_unknown_role_permissions(self):
        self.mock_client.command.return_value = {
            "status_code": 404,
            "body": {"errors": [{"message": "role not found"}]},
        }
        result = self.module.get_role_permissions(role_id="nope", contains=None, include_details=False)
        self.assertIn("error", result)

    # --- manage_user_roles ---------------------------------------------------

    def _manage(self, **kwargs):
        args = {
            "user_uuid": U1,
            "action": "grant",
            "role_ids": ["falconhost_read_only"],
            "expires_at": None,
        }
        return self.module.manage_user_roles(**{**args, **kwargs})

    def test_grant_uses_the_users_cid_and_known_roles(self):
        self.mock_client.command.side_effect = [
            _ok([{"uuid": U1, "cid": CID}]),
            _ok(["falconhost_read_only", "falconhost_admin"]),
            _ok([]),
        ]

        result = self._manage(expires_at="2026-12-01T09:00:00+01:00")

        write = self.mock_client.command.call_args_list[2]
        self.assertEqual(write[0][0], "userRolesActionV2")
        self.assertEqual(
            write[1]["body"],
            {
                "action": "grant",
                "cid": CID,
                "uuid": U1,
                "role_ids": ["falconhost_read_only"],
                "expires_at": "2026-12-01T08:00:00Z",
            },
        )
        self.assertEqual(result["action"], "grant")

    def test_unknown_role_is_refused_before_writing(self):
        self.mock_client.command.side_effect = [
            _ok([{"uuid": U1, "cid": CID}]),
            _ok(["falconhost_admin"]),
        ]

        result = self._manage(role_ids=["made_up_role"])

        self.assertIn("Unknown role", result["error"])
        self.assertEqual(self.mock_client.command.call_count, 2)

    def test_unknown_user_is_refused_before_writing(self):
        self.mock_client.command.return_value = {
            "status_code": 200,
            "body": {"resources": [], "errors": [{"message": "invalid user uuid"}]},
        }

        result = self._manage()

        self.assertIn("No user", result["error"])
        self.assertEqual(self.mock_client.command.call_count, 1)

    def test_manage_roles_input_checks(self):
        for kwargs in (
            {"action": "elevate"},
            {"user_uuid": "jdoe"},
            {"role_ids": []},
            {"action": "revoke", "expires_at": "2026-12-01T00:00:00Z"},
            {"expires_at": "next week"},
        ):
            with self.subTest(kwargs=kwargs):
                self.mock_client.command.reset_mock()
                self.assertIn("error", self._manage(**kwargs))
                self.mock_client.command.assert_not_called()

    # --- other writes --------------------------------------------------------

    def test_reset_credentials(self):
        self.mock_client.command.return_value = _ok([])

        result = self.module.reset_user_credentials(user_uuids=[U1, U1, U2], action="reset_2fa")

        self.mock_client.command.assert_called_once_with(
            "userActionV1", body={"action": {"action_name": "reset_2fa"}, "ids": [U1, U2]}
        )
        self.assertEqual(result["user_uuids"], [U1, U2])

        self.mock_client.command.reset_mock()
        self.assertIn("error", self.module.reset_user_credentials(user_uuids=[U1], action="unlock"))
        self.mock_client.command.assert_not_called()

    def test_create_user_never_sends_a_password(self):
        self.mock_client.command.return_value = {
            "status_code": 201,
            "body": {"resources": [{"uuid": U1, "uid": "new@example.com"}]},
        }

        result = self.module.create_user(
            email=" new@example.com ", first_name="New", last_name=None, validate_only=False
        )

        self.mock_client.command.assert_called_once_with(
            "createUserV1", parameters=None, body={"uid": "new@example.com", "firstName": "New"}
        )
        self.assertTrue(result["created"])
        self.assertEqual(result["user"]["uuid"], U1)

    def test_create_user_validate_only_and_bad_email(self):
        self.mock_client.command.return_value = _ok([])
        result = self.module.create_user(
            email="a@b.co", first_name=None, last_name=None, validate_only=True
        )
        self.assertEqual(self.mock_client.command.call_args[1]["parameters"], {"validate_only": True})
        self.assertFalse(result["created"])

        self.mock_client.command.reset_mock()
        result = self.module.create_user(
            email="not-an-email", first_name=None, last_name=None, validate_only=False
        )
        self.assertIn("error", result)
        self.mock_client.command.assert_not_called()

    def test_update_user(self):
        self.mock_client.command.return_value = _ok([{"uuid": U1}])

        self.module.update_user(user_uuid=U1, first_name=" Jane ", last_name="Doe")

        self.mock_client.command.assert_called_once_with(
            "updateUserV1",
            parameters={"user_uuid": U1},
            body={"firstName": "Jane", "lastName": "Doe"},
        )
        self.mock_client.command.reset_mock()
        self.assertIn("error", self.module.update_user(user_uuid=U1, first_name="", last_name="Doe"))
        self.mock_client.command.assert_not_called()

    def test_delete_user(self):
        self.mock_client.command.return_value = {"status_code": 200, "body": {}}

        result = self.module.delete_user(user_uuid=U1)

        self.mock_client.command.assert_called_once_with(
            "deleteUserV1", parameters={"user_uuid": U1}
        )
        self.assertTrue(result["deleted"])

    def test_delete_user_forbidden_names_the_write_scope(self):
        self.mock_client.command.return_value = {
            "status_code": 403,
            "body": {"errors": [{"message": "access denied"}]},
        }

        result = self.module.delete_user(user_uuid=U1)

        self.assertEqual(result["required_scopes"], ["User Management:write"])


if __name__ == "__main__":
    unittest.main()
