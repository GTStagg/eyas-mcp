"""
Tests for the IDP (Identity Protection) module.
"""

import unittest

from pydantic.fields import FieldInfo

from falcon_mcp.modules.base import READ_ONLY_ANNOTATIONS
from falcon_mcp.modules.idp import IdpModule
from tests.modules.utils.test_modules import TestModules

DEVICE_ID = "0123456789abcdef0123456789abcdef"


class TestIdpModule(TestModules):
    """Test cases for the IDP module."""

    def setUp(self):
        """Set up test fixtures."""
        self.setup_module(IdpModule)

    def test_register_tools(self):
        """Test registering tools with the server."""
        expected_tools = [
            "falcon_idp_investigate_entity",
            "falcon_search_idp_sensors",
            "falcon_search_idp_policy_rules",
            "falcon_search_risky_identities",
            "falcon_get_user_endpoint_history",
            "falcon_correlate_host_identity",
        ]
        self.assert_tools_registered(expected_tools)

    def test_correlation_tools_are_read_only(self):
        """Both correlation tools take the default read-only annotations."""
        self.module.register_tools(self.mock_server)
        for name in ("falcon_get_user_endpoint_history", "falcon_correlate_host_identity"):
            with self.subTest(tool=name):
                self.assert_tool_annotations(name, READ_ONLY_ANNOTATIONS)

    def test_investigate_entity_basic_functionality(self):
        """Test basic entity investigation functionality."""
        # Setup mock GraphQL response for entity resolution
        mock_response = {
            "status_code": 200,
            "body": {
                "data": {
                    "entities": {
                        "nodes": [
                            {
                                "entityId": "test-entity-123",
                                "primaryDisplayName": "Test User",
                                "secondaryDisplayName": "test@example.com",
                                "type": "USER",
                                "riskScore": 75,
                                "riskScoreSeverity": "MEDIUM",
                            }
                        ]
                    }
                }
            },
        }
        self.mock_client.command.return_value = mock_response

        # Call investigate_entity with basic parameters
        result = self.module.investigate_entity(
            entity_names="Test User",
            investigation_types=["entity_details"],
            limit=10,
        )

        # Verify client command was called (at least for entity resolution)
        self.assertTrue(self.mock_client.command.called)

        # Verify result structure
        self.assertIn("investigation_summary", result)
        self.assertIn("entity_details", result)
        self.assertEqual(result["investigation_summary"]["status"], "completed")
        self.assertGreater(result["investigation_summary"]["entity_count"], 0)

    def test_investigate_entity_uses_primary_display_name_pattern(self):
        """Entity name resolution should use wildcard-capable GraphQL patterns."""
        self.mock_client.command.return_value = {
            "status_code": 200,
            "body": {"data": {"entities": {"nodes": []}}},
        }

        self.module.investigate_entity(entity_names="Admin*")

        query = self.mock_client.command.call_args.kwargs["body"]["query"]
        self.assertIn('primaryDisplayNamePattern: "Admin*"', query)
        self.assertNotIn("primaryDisplayNames:", query)

    def test_investigate_entity_uses_email_address_pattern(self):
        """Email resolution should use wildcard-capable email address patterns."""
        self.mock_client.command.return_value = {
            "status_code": 200,
            "body": {"data": {"entities": {"nodes": []}}},
        }

        self.module.investigate_entity(email_addresses="*@example.com")

        query = self.mock_client.command.call_args.kwargs["body"]["query"]
        self.assertIn('secondaryDisplayNamePattern: "*@example.com"', query)
        self.assertIn("types: [USER]", query)
        self.assertNotIn("secondaryDisplayNames:", query)

    def test_investigate_entity_uses_domain_filter(self):
        """Domain resolution should use list-based GraphQL domain filters."""
        self.mock_client.command.return_value = {
            "status_code": 200,
            "body": {"data": {"entities": {"nodes": []}}},
        }

        self.module.investigate_entity(domain_names=["CORP.LOCAL"])

        query = self.mock_client.command.call_args.kwargs["body"]["query"]
        self.assertIn('domains: ["CORP.LOCAL"]', query)
        self.assertNotIn("domainPattern:", query)

    def test_investigate_entity_exact_name_uses_pattern_argument(self):
        """Exact-looking entity names should still use the pattern argument."""
        self.mock_client.command.return_value = {
            "status_code": 200,
            "body": {"data": {"entities": {"nodes": []}}},
        }

        self.module.investigate_entity(entity_names="Administrator")

        query = self.mock_client.command.call_args.kwargs["body"]["query"]
        self.assertIn('primaryDisplayNamePattern: "Administrator"', query)
        self.assertNotIn("primaryDisplayNames:", query)

    def test_investigate_entity_combines_name_pattern_and_domain_filter(self):
        """Name patterns and domain filters should still combine with AND logic."""
        self.mock_client.command.return_value = {
            "status_code": 200,
            "body": {"data": {"entities": {"nodes": []}}},
        }

        self.module.investigate_entity(entity_names="Admin*", domain_names=["CORP.LOCAL"])

        self.assertEqual(self.mock_client.command.call_count, 1)
        query = self.mock_client.command.call_args.kwargs["body"]["query"]
        self.assertIn('primaryDisplayNamePattern: "Admin*"', query)
        self.assertIn('domains: ["CORP.LOCAL"]', query)

    def test_investigate_entity_with_multiple_investigation_types(self):
        """Test entity investigation with multiple investigation types."""
        # Setup mock GraphQL responses for different investigation types
        mock_responses = [
            # Entity resolution response
            {
                "status_code": 200,
                "body": {
                    "data": {
                        "entities": {
                            "nodes": [
                                {
                                    "entityId": "test-entity-456",
                                    "primaryDisplayName": "Admin User",
                                    "secondaryDisplayName": "admin@example.com",
                                }
                            ]
                        }
                    }
                },
            },
            # Entity details response
            {
                "status_code": 200,
                "body": {
                    "data": {
                        "entities": {
                            "nodes": [
                                {
                                    "entityId": "test-entity-456",
                                    "primaryDisplayName": "Admin User",
                                    "secondaryDisplayName": "admin@example.com",
                                    "type": "USER",
                                    "riskScore": 85,
                                    "riskScoreSeverity": "HIGH",
                                    "riskFactors": [
                                        {
                                            "type": "PRIVILEGED_ACCESS",
                                            "severity": "HIGH",
                                        }
                                    ],
                                }
                            ]
                        }
                    }
                },
            },
            # Timeline response
            {
                "status_code": 200,
                "body": {
                    "data": {
                        "timeline": {
                            "nodes": [
                                {
                                    "eventId": "event-123",
                                    "eventType": "AUTHENTICATION",
                                    "timestamp": "2024-01-01T12:00:00Z",
                                }
                            ],
                            "pageInfo": {"hasNextPage": False},
                        }
                    }
                },
            },
            # Relationship analysis response
            {
                "status_code": 200,
                "body": {
                    "data": {
                        "entities": {
                            "nodes": [
                                {
                                    "entityId": "test-entity-456",
                                    "primaryDisplayName": "Admin User",
                                    "associations": [
                                        {
                                            "bindingType": "OWNERSHIP",
                                            "entity": {
                                                "entityId": "server-789",
                                                "primaryDisplayName": "Test Server",
                                            },
                                        }
                                    ],
                                }
                            ]
                        }
                    }
                },
            },
            # Risk assessment response
            {
                "status_code": 200,
                "body": {
                    "data": {
                        "entities": {
                            "nodes": [
                                {
                                    "entityId": "test-entity-456",
                                    "primaryDisplayName": "Admin User",
                                    "riskScore": 85,
                                    "riskScoreSeverity": "HIGH",
                                    "riskFactors": [
                                        {
                                            "type": "PRIVILEGED_ACCESS",
                                            "severity": "HIGH",
                                        }
                                    ],
                                }
                            ]
                        }
                    }
                },
            },
        ]
        self.mock_client.command.side_effect = mock_responses

        # Call investigate_entity with multiple investigation types
        result = self.module.investigate_entity(
            email_addresses="admin@example.com",
            investigation_types=[
                "entity_details",
                "timeline_analysis",
                "relationship_analysis",
                "risk_assessment",
            ],
            limit=50,
            include_associations=True,
            include_accounts=True,
            include_incidents=True,
        )

        # Verify multiple client commands were called
        self.assertGreaterEqual(self.mock_client.command.call_count, 2)

        # Verify result structure contains all investigation types
        self.assertIn("investigation_summary", result)
        self.assertIn("entity_details", result)
        self.assertIn("timeline_analysis", result)
        self.assertIn("relationship_analysis", result)
        self.assertIn("risk_assessment", result)

        # Verify investigation summary
        self.assertEqual(result["investigation_summary"]["status"], "completed")
        self.assertGreater(result["investigation_summary"]["entity_count"], 0)
        self.assertEqual(len(result["investigation_summary"]["investigation_types"]), 4)

    def test_investigate_entity_no_identifiers_error(self):
        """Test error handling when no entity identifiers are provided."""
        # Call investigate_entity without any identifiers
        result = self.module.investigate_entity()

        # Verify error response
        self.assertIn("error", result)
        self.assertIn("investigation_summary", result)
        self.assertEqual(result["investigation_summary"]["status"], "failed")
        self.assertEqual(result["investigation_summary"]["entity_count"], 0)

        # Verify no API calls were made
        self.assertFalse(self.mock_client.command.called)

    def test_investigate_entity_no_entities_found(self):
        """Test handling when no entities are found matching criteria."""
        # Setup mock response with no entities
        mock_response = {
            "status_code": 200,
            "body": {"data": {"entities": {"nodes": []}}},
        }
        self.mock_client.command.return_value = mock_response

        # Call investigate_entity
        result = self.module.investigate_entity(entity_names="NonExistent User")

        # Verify result indicates no entities found
        self.assertIn("error", result)
        self.assertIn("investigation_summary", result)
        self.assertEqual(result["investigation_summary"]["status"], "failed")
        self.assertEqual(result["investigation_summary"]["entity_count"], 0)
        self.assertIn("search_criteria", result)

    def test_investigate_entity_error_response_has_no_fieldinfo(self):
        """Error responses must not leak raw Pydantic FieldInfo objects (issue #384)."""
        # Empty entity resolution so the error path builds search_criteria
        self.mock_client.command.return_value = {
            "status_code": 200,
            "body": {"data": {"entities": {"nodes": []}}},
        }
        result = self.module.investigate_entity(entity_names="NonExistent User")

        def assert_no_fieldinfo(obj):
            if isinstance(obj, dict):
                for value in obj.values():
                    assert_no_fieldinfo(value)
            elif isinstance(obj, list):
                for value in obj:
                    assert_no_fieldinfo(value)
            else:
                self.assertNotIsInstance(obj, FieldInfo)

        assert_no_fieldinfo(result)
        self.assertEqual(result["search_criteria"]["entity_ids"], None)
        self.assertEqual(result["search_criteria"]["entity_names"], "NonExistent User")

    def test_investigate_entity_zero_args_no_fieldinfo_leak(self):
        """Zero-argument call must not leak FieldInfo objects in the error response."""
        result = self.module.investigate_entity()

        # Verify validation error returned
        self.assertIn("error", result)
        self.assertIn("investigation_summary", result)
        self.assertEqual(result["investigation_summary"]["status"], "failed")

        # Verify investigation_types resolved to actual default, not FieldInfo
        self.assertEqual(
            result["investigation_summary"]["investigation_types"],
            ["entity_details"],
        )

        # Recursive check: no FieldInfo objects anywhere in the response
        def assert_no_fieldinfo(obj):
            if isinstance(obj, dict):
                for value in obj.values():
                    assert_no_fieldinfo(value)
            elif isinstance(obj, list):
                for value in obj:
                    assert_no_fieldinfo(value)
            else:
                self.assertNotIsInstance(obj, FieldInfo)

        assert_no_fieldinfo(result)

    def test_investigate_entity_with_geographic_location_data(self):
        """Test entity investigation includes geographic location data in timeline analysis."""
        # Setup mock GraphQL responses with geographic location data
        mock_responses = [
            # Entity resolution response
            {
                "status_code": 200,
                "body": {
                    "data": {
                        "entities": {
                            "nodes": [
                                {
                                    "entityId": "test-entity-geo-123",
                                    "primaryDisplayName": "Global User",
                                    "secondaryDisplayName": "global@example.com",
                                }
                            ]
                        }
                    }
                },
            },
            # Timeline response with geographic location data
            {
                "status_code": 200,
                "body": {
                    "data": {
                        "timeline": {
                            "nodes": [
                                {
                                    "eventId": "auth-event-123",
                                    "eventType": "AUTHENTICATION",
                                    "eventSeverity": "MEDIUM",
                                    "timestamp": "2024-01-01T12:00:00Z",
                                    "sourceEntity": {
                                        "entityId": "test-entity-geo-123",
                                        "primaryDisplayName": "Global User",
                                    },
                                    "targetEntity": {
                                        "entityId": "server-456",
                                        "primaryDisplayName": "Corporate Server",
                                    },
                                    "geoLocation": {
                                        "country": "United States",
                                        "countryCode": "US",
                                        "city": "New York",
                                        "cityCode": "NYC",
                                        "latitude": 40.7128,
                                        "longitude": -74.0060,
                                    },
                                    "locationAssociatedWithUser": True,
                                    "userDisplayName": "Global User",
                                    "endpointDisplayName": "NYC-Workstation-01",
                                    "ipAddress": "192.168.1.100",
                                },
                                {
                                    "eventId": "auth-event-456",
                                    "eventType": "AUTHENTICATION",
                                    "eventSeverity": "HIGH",
                                    "timestamp": "2024-01-02T08:30:00Z",
                                    "sourceEntity": {
                                        "entityId": "test-entity-geo-123",
                                        "primaryDisplayName": "Global User",
                                    },
                                    "targetEntity": {
                                        "entityId": "server-789",
                                        "primaryDisplayName": "Remote Server",
                                    },
                                    "geoLocation": {
                                        "country": "Germany",
                                        "countryCode": "DE",
                                        "city": "Berlin",
                                        "cityCode": "BER",
                                        "latitude": 52.5200,
                                        "longitude": 13.4050,
                                    },
                                    "locationAssociatedWithUser": True,
                                    "userDisplayName": "Global User",
                                    "endpointDisplayName": "BER-Laptop-02",
                                    "ipAddress": "10.0.0.50",
                                },
                            ],
                            "pageInfo": {"hasNextPage": False},
                        }
                    }
                },
            },
        ]
        self.mock_client.command.side_effect = mock_responses

        # Call investigate_entity with timeline analysis to get geographic data
        result = self.module.investigate_entity(
            entity_names="Global User",
            investigation_types=["timeline_analysis"],
            timeline_start_time="2024-01-01T00:00:00Z",
            timeline_end_time="2024-01-02T23:59:59Z",
            limit=50,
        )

        # Verify result structure
        self.assertIn("investigation_summary", result)
        self.assertIn("timeline_analysis", result)
        self.assertEqual(result["investigation_summary"]["status"], "completed")

        # Verify geographic location data is present in timeline events
        timeline_data = result["timeline_analysis"]["timelines"][0]["timeline"]
        self.assertGreater(len(timeline_data), 0)

        # Check first event has geographic location data
        first_event = timeline_data[0]
        self.assertIn("geoLocation", first_event)
        self.assertIn("country", first_event["geoLocation"])
        self.assertIn("countryCode", first_event["geoLocation"])
        self.assertIn("city", first_event["geoLocation"])
        self.assertIn("cityCode", first_event["geoLocation"])
        self.assertIn("latitude", first_event["geoLocation"])
        self.assertIn("longitude", first_event["geoLocation"])

        # Verify geographic location values
        self.assertEqual(first_event["geoLocation"]["country"], "United States")
        self.assertEqual(first_event["geoLocation"]["countryCode"], "US")
        self.assertEqual(first_event["geoLocation"]["city"], "New York")
        self.assertEqual(first_event["geoLocation"]["cityCode"], "NYC")

        # Check additional location fields
        self.assertIn("locationAssociatedWithUser", first_event)
        self.assertIn("userDisplayName", first_event)
        self.assertIn("endpointDisplayName", first_event)
        self.assertIn("ipAddress", first_event)

        # Verify second event has different country (multi-location user)
        second_event = timeline_data[1]
        self.assertEqual(second_event["geoLocation"]["country"], "Germany")
        self.assertEqual(second_event["geoLocation"]["countryCode"], "DE")

    def test_investigate_entity_with_geo_location_associations(self):
        """Test entity investigation includes geographic location associations."""
        # Setup mock GraphQL responses with geographic location associations
        mock_responses = [
            # Entity resolution response
            {
                "status_code": 200,
                "body": {
                    "data": {
                        "entities": {
                            "nodes": [
                                {
                                    "entityId": "test-entity-assoc-456",
                                    "primaryDisplayName": "Travel User",
                                    "secondaryDisplayName": "travel@example.com",
                                }
                            ]
                        }
                    }
                },
            },
            # Entity details response with geographic associations
            {
                "status_code": 200,
                "body": {
                    "data": {
                        "entities": {
                            "nodes": [
                                {
                                    "entityId": "test-entity-assoc-456",
                                    "primaryDisplayName": "Travel User",
                                    "secondaryDisplayName": "travel@example.com",
                                    "type": "USER",
                                    "riskScore": 60,
                                    "riskScoreSeverity": "MEDIUM",
                                    "associations": [
                                        {
                                            "bindingType": "LOCATION_ACCESS",
                                            "geoLocation": {
                                                "country": "France",
                                                "countryCode": "FR",
                                                "city": "Paris",
                                                "cityCode": "PAR",
                                                "latitude": 48.8566,
                                                "longitude": 2.3522,
                                            },
                                        },
                                        {
                                            "bindingType": "LOCATION_ACCESS",
                                            "geoLocation": {
                                                "country": "Japan",
                                                "countryCode": "JP",
                                                "city": "Tokyo",
                                                "cityCode": "TYO",
                                                "latitude": 35.6762,
                                                "longitude": 139.6503,
                                            },
                                        },
                                    ],
                                }
                            ]
                        }
                    }
                },
            },
        ]
        self.mock_client.command.side_effect = mock_responses

        # Call investigate_entity with entity details to get geographic associations
        result = self.module.investigate_entity(
            entity_names="Travel User",
            investigation_types=["entity_details"],
            include_associations=True,
            limit=50,
        )

        # Verify result structure
        self.assertIn("investigation_summary", result)
        self.assertIn("entity_details", result)
        self.assertEqual(result["investigation_summary"]["status"], "completed")

        # Verify geographic location associations are present
        entity_data = result["entity_details"]["entities"][0]
        self.assertIn("associations", entity_data)
        associations = entity_data["associations"]
        self.assertGreater(len(associations), 0)

        # Check geographic location associations
        geo_associations = [
            assoc for assoc in associations if "geoLocation" in assoc
        ]
        self.assertGreater(len(geo_associations), 0)

        # Verify first geographic association
        first_geo_assoc = geo_associations[0]
        self.assertIn("geoLocation", first_geo_assoc)
        geo_location = first_geo_assoc["geoLocation"]
        self.assertIn("country", geo_location)
        self.assertIn("countryCode", geo_location)
        self.assertIn("city", geo_location)
        self.assertIn("cityCode", geo_location)
        self.assertIn("latitude", geo_location)
        self.assertIn("longitude", geo_location)

        # Verify geographic location values
        self.assertEqual(geo_location["country"], "France")
        self.assertEqual(geo_location["countryCode"], "FR")

    def test_investigate_entity_multi_country_detection(self):
        """Test detection of users active in multiple countries."""
        # Setup mock GraphQL responses simulating user activity in 4+ countries
        mock_responses = [
            # Entity resolution response
            {
                "status_code": 200,
                "body": {
                    "data": {
                        "entities": {
                            "nodes": [
                                {
                                    "entityId": "multi-country-user-789",
                                    "primaryDisplayName": "Global Executive",
                                    "secondaryDisplayName": "executive@example.com",
                                }
                            ]
                        }
                    }
                },
            },
            # Timeline response with activities from multiple countries
            {
                "status_code": 200,
                "body": {
                    "data": {
                        "timeline": {
                            "nodes": [
                                {
                                    "eventId": "event-us-001",
                                    "eventType": "SUCCESSFUL_AUTHENTICATION",
                                    "timestamp": "2024-01-01T09:00:00Z",
                                    "geoLocation": {
                                        "country": "United States",
                                        "countryCode": "US",
                                        "city": "San Francisco",
                                        "cityCode": "SFO",
                                    },
                                    "locationAssociatedWithUser": True,
                                },
                                {
                                    "eventId": "event-uk-002",
                                    "eventType": "SUCCESSFUL_AUTHENTICATION",
                                    "timestamp": "2024-01-02T14:30:00Z",
                                    "geoLocation": {
                                        "country": "United Kingdom",
                                        "countryCode": "GB",
                                        "city": "London",
                                        "cityCode": "LDN",
                                    },
                                    "locationAssociatedWithUser": True,
                                },
                                {
                                    "eventId": "event-sg-003",
                                    "eventType": "SUCCESSFUL_AUTHENTICATION",
                                    "timestamp": "2024-01-03T22:15:00Z",
                                    "geoLocation": {
                                        "country": "Singapore",
                                        "countryCode": "SG",
                                        "city": "Singapore",
                                        "cityCode": "SIN",
                                    },
                                    "locationAssociatedWithUser": True,
                                },
                                {
                                    "eventId": "event-au-004",
                                    "eventType": "SUCCESSFUL_AUTHENTICATION",
                                    "timestamp": "2024-01-04T05:45:00Z",
                                    "geoLocation": {
                                        "country": "Australia",
                                        "countryCode": "AU",
                                        "city": "Sydney",
                                        "cityCode": "SYD",
                                    },
                                    "locationAssociatedWithUser": True,
                                },
                            ],
                            "pageInfo": {"hasNextPage": False},
                        }
                    }
                },
            },
        ]
        self.mock_client.command.side_effect = mock_responses

        # Call investigate_entity with timeline analysis
        result = self.module.investigate_entity(
            entity_names="Global Executive",
            investigation_types=["timeline_analysis"],
            timeline_start_time="2024-01-01T00:00:00Z",
            timeline_end_time="2024-01-04T23:59:59Z",
            limit=100,
        )

        # Verify result structure
        self.assertIn("timeline_analysis", result)
        timeline_events = result["timeline_analysis"]["timelines"][0]["timeline"]
        self.assertEqual(len(timeline_events), 4)

        # Extract unique countries from timeline events
        countries = set()
        for event in timeline_events:
            if "geoLocation" in event and "country" in event["geoLocation"]:
                countries.add(event["geoLocation"]["country"])

        # Verify user has been active in 4 different countries
        expected_countries = {"United States", "United Kingdom", "Singapore", "Australia"}
        self.assertEqual(countries, expected_countries)
        self.assertEqual(len(countries), 4)

        # Verify each event has proper geographic location structure
        for event in timeline_events:
            self.assertIn("geoLocation", event)
            geo_loc = event["geoLocation"]
            self.assertIn("country", geo_loc)
            self.assertIn("countryCode", geo_loc)
            self.assertIn("city", geo_loc)
            self.assertIn("cityCode", geo_loc)
            self.assertTrue(event.get("locationAssociatedWithUser", False))

    def test_investigate_entity_file_operation_geographic_data(self):
        """Test geographic location data in file operation events (targetEntity only)."""
        # Setup mock response for file operation event with geographic data
        mock_responses = [
            # Entity resolution response
            {
                "status_code": 200,
                "body": {
                    "data": {
                        "entities": {
                            "nodes": [
                                {
                                    "entityId": "file-user-123",
                                    "primaryDisplayName": "File User",
                                }
                            ]
                        }
                    }
                },
            },
            # Timeline response with file operation event
            {
                "status_code": 200,
                "body": {
                    "data": {
                        "timeline": {
                            "nodes": [
                                {
                                    "eventId": "file-op-001",
                                    "eventType": "FILE_OPERATION",
                                    "timestamp": "2024-01-01T15:30:00Z",
                                    "targetEntity": {
                                        "entityId": "file-server-456",
                                        "primaryDisplayName": "Shared File Server",
                                    },
                                    "geoLocation": {
                                        "country": "Canada",
                                        "countryCode": "CA",
                                        "city": "Toronto",
                                        "cityCode": "YYZ",
                                        "latitude": 43.6532,
                                        "longitude": -79.3832,
                                    },
                                    "locationAssociatedWithUser": True,
                                    "userDisplayName": "File User",
                                    "endpointDisplayName": "TOR-Desktop-01",
                                    "ipAddress": "172.16.0.25",
                                }
                            ],
                            "pageInfo": {"hasNextPage": False},
                        }
                    }
                },
            },
        ]
        self.mock_client.command.side_effect = mock_responses

        # Call investigate_entity with timeline analysis
        result = self.module.investigate_entity(
            entity_names="File User",
            investigation_types=["timeline_analysis"],
            limit=50,
        )

        # Verify file operation event has geographic data
        timeline_events = result["timeline_analysis"]["timelines"][0]["timeline"]
        file_event = timeline_events[0]

        # Verify event structure (should have targetEntity but no sourceEntity for file operations)
        self.assertIn("targetEntity", file_event)
        self.assertNotIn("sourceEntity", file_event)

        # Verify geographic location data is present
        self.assertIn("geoLocation", file_event)
        geo_loc = file_event["geoLocation"]
        self.assertEqual(geo_loc["country"], "Canada")
        self.assertEqual(geo_loc["countryCode"], "CA")
        self.assertEqual(geo_loc["city"], "Toronto")

        # Verify additional location context
        self.assertIn("locationAssociatedWithUser", file_event)
        self.assertIn("userDisplayName", file_event)
        self.assertIn("endpointDisplayName", file_event)
        self.assertIn("ipAddress", file_event)


    # ==========================================
    # Bare-wildcard guard tests (Change 2)
    # ==========================================

    def test_bare_wildcard_entity_names_rejected(self):
        """entity_names='*' must return an error dict without calling the API."""
        result = self.module.investigate_entity(entity_names="*")

        self.assertIn("error", result)
        self.assertIn("investigation_summary", result)
        self.assertEqual(result["investigation_summary"]["status"], "failed")
        self.assertFalse(self.mock_client.command.called)

    def test_bare_wildcard_email_addresses_rejected(self):
        """email_addresses='*' must return an error dict without calling the API."""
        result = self.module.investigate_entity(email_addresses="*")

        self.assertIn("error", result)
        self.assertIn("investigation_summary", result)
        self.assertEqual(result["investigation_summary"]["status"], "failed")
        self.assertFalse(self.mock_client.command.called)

    def test_bare_wildcard_variants_rejected(self):
        """'**' and '* ' (all stars/spaces) must be rejected without calling the API."""
        for bad_value in ["**", "* ", " * "]:
            with self.subTest(entity_names=bad_value):
                self.mock_client.command.reset_mock()
                result = self.module.investigate_entity(entity_names=bad_value)
                self.assertIn("error", result)
                self.assertEqual(result["investigation_summary"]["status"], "failed")
                self.assertFalse(self.mock_client.command.called)

    def test_partial_wildcard_entity_names_accepted(self):
        """entity_names='Admin*' is a legitimate pattern and must reach the API."""
        self.mock_client.command.return_value = {
            "status_code": 200,
            "body": {"data": {"entities": {"nodes": []}}},
        }

        self.module.investigate_entity(entity_names="Admin*")

        self.assertTrue(self.mock_client.command.called)

    def test_partial_wildcard_email_addresses_accepted(self):
        """email_addresses='*@example.com' is a legitimate pattern and must reach the API."""
        self.mock_client.command.return_value = {
            "status_code": 200,
            "body": {"data": {"entities": {"nodes": []}}},
        }

        self.module.investigate_entity(email_addresses="*@example.com")

        self.assertTrue(self.mock_client.command.called)

    def test_timeline_query_escapes_string_values(self):
        """A quote in an argument must not break out of the GraphQL string."""
        payload = 'x"]}) { nodes { eventId } } } mutation { evil } #'

        query = self.module._build_timeline_query(
            entity_id=payload,
            start_time=payload,
            end_time=payload,
            event_types=None,
            limit=10,
        )

        self.assertNotIn('x"]})', query)
        self.assertEqual(query.count('x\\"]})'), 3)

    def test_relationship_query_escapes_entity_id(self):
        """Relationship analysis must quote the entity ID the same way."""
        query = self.module._build_relationship_analysis_query(
            entity_id='x"], first: 1) { } } mutation { evil } #',
            relationship_depth=1,
            include_risk_context=False,
            limit=10,
        )

        self.assertNotIn('x"],', query)
        self.assertIn('x\\"],', query)

    def test_timeline_query_keeps_valid_event_types_unquoted(self):
        """GraphQL enums must stay unquoted or the API rejects them."""
        query = self.module._build_timeline_query(
            entity_id="entity",
            start_time=None,
            end_time=None,
            event_types=["ACTIVITY", "THREAT"],
            limit=10,
        )

        self.assertIn("categories: [ACTIVITY, THREAT]", query)

    def test_investigate_entity_rejects_injected_event_types(self):
        """Enums can't be escaped, so a bad value must stop before any API call."""
        result = self.module.investigate_entity(
            entity_ids=["entity"],
            investigation_types=["timeline_analysis"],
            timeline_event_types=["ACTIVITY]) { x } } mutation { evil } #"],
        )

        self.assertIn("Invalid timeline_event_types", result["error"])
        self.assertEqual(result["investigation_summary"]["status"], "failed")
        self.mock_client.command.assert_not_called()


    # ==========================================
    # search_idp_sensors
    # ==========================================

    def test_search_idp_sensors_queries_then_hydrates(self):
        """Sensor IDs come from a GET query, then details from a POST body."""
        self.mock_client.command.side_effect = [
            {
                "status_code": 200,
                "body": {
                    "resources": ["dc-2", "dc-1"],
                    "meta": {"pagination": {"offset": 0, "limit": 50, "total": 2}},
                },
            },
            {
                "status_code": 200,
                "body": {
                    "resources": [
                        {"device_id": "dc-1", "hostname": "DC01", "status": "Protected"},
                        {"device_id": "dc-2", "hostname": "DC02", "status": "Degraded"},
                    ]
                },
            },
        ]

        result = self.module.search_idp_sensors(
            filter="hostname:'DC*'", limit=50, offset=None, sort="hostname.asc"
        )

        query_call, details_call = self.mock_client.command.call_args_list
        self.assertEqual(query_call.args[0], "QuerySensorsByFilter")
        self.assertEqual(
            query_call.kwargs["parameters"],
            {"filter": "hostname:'DC*'", "limit": 50, "sort": "hostname.asc"},
        )
        self.assertEqual(details_call.args[0], "GetSensorDetails")
        self.assertEqual(details_call.kwargs["body"], {"ids": ["dc-2", "dc-1"]})

        self.assertEqual([s["device_id"] for s in result["results"]], ["dc-2", "dc-1"])
        self.assertEqual(result["filter_used"], "hostname:'DC*'")
        self.assert_pagination(result, total=2)

    def test_search_idp_sensors_empty(self):
        """No sensors means no details call."""
        self.mock_client.command.return_value = {
            "status_code": 200,
            "body": {"resources": [], "meta": {"pagination": {"total": 0}}},
        }

        result = self.module.search_idp_sensors()

        self.assertEqual(self.mock_client.command.call_count, 1)
        self.assertEqual(result["results"], [])
        self.assert_pagination(result, total=0)

    def test_search_idp_sensors_error(self):
        """A failed query is returned as an error, not an empty result."""
        self.mock_client.command.return_value = {
            "status_code": 403,
            "body": {"errors": [{"message": "access denied"}]},
        }

        result = self.module.search_idp_sensors(filter=None, limit=10, offset=None, sort=None)

        self.assertIsInstance(result, list)
        self.assertIn("error", result[0])

    # ==========================================
    # search_idp_policy_rules
    # ==========================================

    def test_search_idp_policy_rules_passes_filters_and_hydrates(self):
        """Filters go to the query string; details are fetched by ID with GET."""
        self.mock_client.command.side_effect = [
            {"status_code": 200, "body": {"resources": ["rule-1", "rule-2"]}},
            {
                "status_code": 200,
                "body": {
                    "resources": [
                        {"id": "rule-1", "name": "Block legacy auth", "enabled": True},
                        {"id": "rule-2", "name": "MFA for admins", "enabled": True},
                    ]
                },
            },
        ]

        result = self.module.search_idp_policy_rules(
            enabled=True, simulation_mode=False, name=None, limit=100
        )

        query_call, details_call = self.mock_client.command.call_args_list
        self.assertEqual(query_call.args[0], "get_policy_rules_query")
        self.assertEqual(
            query_call.kwargs["parameters"], {"enabled": True, "simulation_mode": False}
        )
        self.assertEqual(details_call.args[0], "get_policy_rules")
        self.assertEqual(details_call.kwargs["parameters"], {"ids": ["rule-1", "rule-2"]})

        self.assertEqual(len(result["results"]), 2)
        self.assert_pagination(result, total=2)

    def test_search_idp_policy_rules_batches_by_100_and_honors_limit(self):
        """get_policy_rules caps IDs at 100, and limit caps what is hydrated."""
        rule_ids = [f"rule-{i}" for i in range(250)]

        def respond(operation, **kwargs):
            if operation == "get_policy_rules_query":
                return {"status_code": 200, "body": {"resources": rule_ids}}
            ids = kwargs["parameters"]["ids"]
            return {"status_code": 200, "body": {"resources": [{"id": i} for i in ids]}}

        self.mock_client.command.side_effect = respond

        result = self.module.search_idp_policy_rules(limit=220)

        detail_calls = self.mock_client.command.call_args_list[1:]
        self.assertEqual(
            [len(call.kwargs["parameters"]["ids"]) for call in detail_calls], [100, 100, 20]
        )
        self.assertEqual(len(result["results"]), 220)
        # The total reports every matching rule, not just those returned
        self.assert_pagination(result, total=250)

    def test_search_idp_policy_rules_empty(self):
        """No rules means no details call and a zero total."""
        self.mock_client.command.return_value = {"status_code": 200, "body": {"resources": []}}

        result = self.module.search_idp_policy_rules()

        self.assertEqual(self.mock_client.command.call_count, 1)
        self.assertEqual(result["results"], [])
        self.assert_pagination(result, total=0)

    def test_search_idp_policy_rules_details_error(self):
        """A failed details call is surfaced."""
        self.mock_client.command.side_effect = [
            {"status_code": 200, "body": {"resources": ["rule-1"]}},
            {"status_code": 500, "body": {"errors": [{"message": "boom"}]}},
        ]

        result = self.module.search_idp_policy_rules()

        self.assertIsInstance(result, list)
        self.assertIn("error", result[0])

    # ==========================================
    # search_risky_identities
    # ==========================================

    def _risky_response(self, nodes=None, has_next=False, cursor=None):
        return {
            "status_code": 200,
            "body": {
                "data": {
                    "entities": {
                        "nodes": nodes or [],
                        "pageInfo": {"hasNextPage": has_next, "endCursor": cursor},
                    }
                }
            },
        }

    def test_search_risky_identities_default_query(self):
        """The default ranks active users by risk score, highest first."""
        node = {
            "entityId": "e-1",
            "primaryDisplayName": "Jane Admin",
            "riskScore": 0.92,
            "riskScoreSeverity": "HIGH",
        }
        self.mock_client.command.return_value = self._risky_response([node], True, "cursor-1")

        result = self.module.search_risky_identities()

        call = self.mock_client.command.call_args
        self.assertEqual(call.args[0], "api_preempt_proxy_post_graphql")
        query = call.kwargs["body"]["query"]
        self.assertIn("first: 25", query)
        self.assertIn("sortKey: RISK_SCORE", query)
        self.assertIn("sortOrder: DESCENDING", query)
        self.assertIn("types: [USER]", query)
        self.assertIn("archived: false", query)
        self.assertNotIn("minRiskScoreSeverity", query)
        self.assertNotIn("after:", query)

        self.assertEqual(result["results"], [node])
        self.assertEqual(result["pagination"], {"total": None, "next": "cursor-1"})

    def test_search_risky_identities_optional_filters(self):
        """Severity and type are normalized enums; domains and cursor are JSON strings."""
        self.mock_client.command.return_value = self._risky_response()

        result = self.module.search_risky_identities(
            limit=5,
            entity_type="endpoint",
            min_risk_severity="medium",
            domain_names=["CORP.LOCAL"],
            after="abc==",
        )

        query = self.mock_client.command.call_args.kwargs["body"]["query"]
        self.assertIn("first: 5", query)
        self.assertIn("types: [ENDPOINT]", query)
        self.assertIn("minRiskScoreSeverity: MEDIUM", query)
        self.assertIn('domains: ["CORP.LOCAL"]', query)
        self.assertIn('after: "abc=="', query)
        self.assert_pagination(result, total=None)

    def test_search_risky_identities_escapes_cursor(self):
        """A hostile cursor stays inside its GraphQL string."""
        payload = 'x") { nodes { entityId } } } mutation { evil } #'
        self.mock_client.command.return_value = self._risky_response()

        self.module.search_risky_identities(after=payload)

        query = self.mock_client.command.call_args.kwargs["body"]["query"]
        self.assertNotIn('x")', query)
        self.assertIn('after: "x\\") { nodes', query)

    def test_search_risky_identities_domain_cannot_break_out(self):
        """A hostile domain name can't close the list or the string."""
        self.mock_client.command.return_value = self._risky_response()

        self.module.search_risky_identities(domain_names=['CORP"]) { x } } mutation { evil } #'])

        query = self.mock_client.command.call_args.kwargs["body"]["query"]
        self.assertNotIn('CORP"]', query)
        self.assertNotIn('CORP\\"]', query)
        self.assertIn('domains: ["CORP]) { x } } mutation { evil } #"]', query)

    def test_search_risky_identities_rejects_injected_entity_type(self):
        """An unlisted entity type stops before any API call."""
        result = self.module.search_risky_identities(
            entity_type="USER]) { x } } mutation { evil } #"
        )

        self.assertIn("Invalid entity_type", result[0]["error"])
        self.mock_client.command.assert_not_called()

    def test_search_risky_identities_rejects_unlisted_enum_lookalike(self):
        """A valid-looking enum that isn't on the allowlist is still rejected."""
        result = self.module.search_risky_identities(min_risk_severity="CRITICAL")

        self.assertIn("Invalid min_risk_severity", result[0]["error"])
        self.mock_client.command.assert_not_called()

    def test_search_risky_identities_rejects_injected_severity(self):
        """Severity is unquoted in the query, so injection must be refused."""
        result = self.module.search_risky_identities(
            min_risk_severity="HIGH) { x } } mutation { evil } #"
        )

        self.assertIn("Invalid min_risk_severity", result[0]["error"])
        self.mock_client.command.assert_not_called()

    def test_search_risky_identities_rejects_non_integer_limit(self):
        """limit is written bare, so only a real integer in range is accepted."""
        for bad in ["5) { x }", 5.5, True, 0, 201]:
            with self.subTest(limit=bad):
                result = self.module.search_risky_identities(limit=bad)
                self.assertIn("limit must be an integer", result[0]["error"])
        self.mock_client.command.assert_not_called()

    def test_risky_identities_builder_refuses_unvalidated_values(self):
        """The builder itself refuses values that would be written unquoted."""
        with self.assertRaises(ValueError):
            self.module._build_risky_identities_query("5", "USER", None, None, None)
        with self.assertRaises(ValueError):
            self.module._build_risky_identities_query(5, "USER] evil", None, None, None)
        with self.assertRaises(ValueError):
            self.module._build_risky_identities_query(5, "USER", "HIGH evil", None, None)

    def test_search_risky_identities_surfaces_graphql_errors(self):
        """GraphQL errors arrive in a 200 body and must not look like empty results."""
        self.mock_client.command.return_value = {
            "status_code": 200,
            "body": {"errors": [{"message": "Cannot query field"}], "data": None},
        }

        result = self.module.search_risky_identities()

        self.assertIn("Cannot query field", result[0]["error"])

    def test_search_risky_identities_http_error(self):
        """An HTTP failure is returned as an error."""
        self.mock_client.command.return_value = {
            "status_code": 403,
            "body": {"errors": [{"message": "access denied"}]},
        }

        result = self.module.search_risky_identities()

        self.assertIn("error", result[0])

    # ==========================================
    # get_user_endpoint_history
    # ==========================================

    def test_endpoint_history_queries_then_hydrates_and_ranks(self):
        """Hosts are found by last_login_user, hydrated, projected and ranked newest first."""
        self.mock_client.command.side_effect = [
            {
                "status_code": 200,
                "body": {
                    "resources": ["aid-1", "aid-2"],
                    "meta": {"pagination": {"offset": 0, "limit": 25, "total": 2}},
                },
            },
            {
                "status_code": 200,
                "body": {
                    "resources": [
                        {
                            "device_id": "aid-1",
                            "hostname": "WS-OLD",
                            "last_login_user": "jdoe",
                            "last_login_timestamp": "2026-11-01T08:00:00Z",
                            "platform_name": "Windows",
                            "os_product_name": "Windows 11 Pro",
                            "last_seen": "2026-11-06T08:00:00Z",
                            "local_ip": "10.0.0.5",
                        },
                        {
                            "device_id": "aid-2",
                            "hostname": "WS-NEW",
                            "last_login_user": "jdoe",
                            "last_login_timestamp": "2026-11-05T08:00:00Z",
                            "platform_name": "Windows",
                            "os_product_name": "Windows 11 Pro",
                            "last_seen": "2026-11-07T08:00:00Z",
                        },
                    ]
                },
            },
        ]

        result = self.module.get_user_endpoint_history(user_name="JDoe", hours=48, limit=25)

        query_call, details_call = self.mock_client.command.call_args_list
        self.assertEqual(query_call.args[0], "QueryDevicesByFilter")
        params = query_call.kwargs["parameters"]
        self.assertRegex(
            params["filter"],
            r"^last_login_user:'jdoe'\+last_login_timestamp:>'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ'$",
        )
        self.assertEqual(params["limit"], 25)
        self.assertEqual(params["sort"], "last_login_timestamp.desc")
        self.assertEqual(details_call.args[0], "PostDeviceDetailsV2")
        self.assertEqual(details_call.kwargs["body"], {"ids": ["aid-1", "aid-2"]})

        self.assertEqual([h["hostname"] for h in result["results"]], ["WS-NEW", "WS-OLD"])
        self.assertEqual(
            set(result["results"][0]),
            {
                "device_id",
                "hostname",
                "last_login_user",
                "last_login_timestamp",
                "platform_name",
                "os_product_name",
                "last_seen",
            },
        )
        self.assertEqual(result["filter_used"], params["filter"])
        self.assert_pagination(result, total=2)

    def test_endpoint_history_defaults(self):
        """Field defaults resolve to a 7-day window capped at 25 hosts."""
        self.mock_client.command.return_value = {
            "status_code": 200,
            "body": {"resources": [], "meta": {"pagination": {"total": 0}}},
        }

        result = self.module.get_user_endpoint_history(user_name="svc_backup")

        self.assertEqual(self.mock_client.command.call_count, 1)
        params = self.mock_client.command.call_args.kwargs["parameters"]
        self.assertEqual(params["limit"], 25)
        self.assertTrue(params["filter"].startswith("last_login_user:'svc_backup'+"))
        self.assertEqual(result["results"], [])
        self.assert_pagination(result, total=0)

    def test_endpoint_history_rejects_hostile_user_names(self):
        """Anything that could close the FQL string or widen the match never reaches the API."""
        hostile = [
            "jdoe'+last_login_user:*'",
            "jdoe'",
            "jd\\'oe",
            "CORP\\jdoe",
            'jdoe"',
            "jdoe\n",
            "jd\x00oe",
            "jd\toe",
            "*",
            "jdoe*",
            "jdoe,admin",
            "jdoe+platform_name:'Linux'",
            "",
            "   ",
            "a" * 105,
            None,
            123,
        ]
        for bad in hostile:
            with self.subTest(user_name=bad):
                result = self.module.get_user_endpoint_history(user_name=bad)
                self.assertIsInstance(result, list)
                self.assertIn("error", result[0])
        self.mock_client.command.assert_not_called()

    def test_endpoint_history_accepts_ordinary_account_names(self):
        """Real-world logon names pass validation."""
        self.mock_client.command.return_value = {"status_code": 200, "body": {"resources": []}}
        for good in ["jdoe", "j.doe-admin", "svc_sql$", "jdoe@corp.example.com", "John Smith"]:
            with self.subTest(user_name=good):
                result = self.module.get_user_endpoint_history(user_name=good)
                self.assertIn("results", result)

    def test_endpoint_history_rejects_out_of_range_numbers(self):
        """hours and limit are checked even when called directly, bypassing Pydantic."""
        for kwargs in [
            {"hours": 0},
            {"hours": 2161},
            {"hours": "24"},
            {"hours": True},
            {"limit": 0},
            {"limit": 101},
            {"limit": 2.5},
        ]:
            with self.subTest(**kwargs):
                result = self.module.get_user_endpoint_history(user_name="jdoe", **kwargs)
                self.assertIn("error", result[0])
        self.mock_client.command.assert_not_called()

    def test_endpoint_history_query_error(self):
        """A failed host query is surfaced as an error."""
        self.mock_client.command.return_value = {
            "status_code": 403,
            "body": {"errors": [{"message": "access denied"}]},
        }

        result = self.module.get_user_endpoint_history(user_name="jdoe")

        self.assertIsInstance(result, list)
        self.assertIn("error", result[0])

    # ==========================================
    # correlate_host_identity
    # ==========================================

    @staticmethod
    def _host_response(**overrides):
        host = {
            "device_id": DEVICE_ID,
            "hostname": "WS-01",
            "machine_domain": "corp.example.com",
            "last_login_user": "jdoe",
            "last_login_timestamp": "2026-11-06T09:00:00Z",
            "platform_name": "Windows",
            "local_ip": "10.0.0.5",
        }
        host.update(overrides)
        return {"status_code": 200, "body": {"resources": [host]}}

    @staticmethod
    def _identity_response(nodes):
        return {"status_code": 200, "body": {"data": {"entities": {"nodes": nodes}}}}

    @staticmethod
    def _entity(entity_id, domain, sam="jdoe", score=0.8):
        return {
            "entityId": entity_id,
            "primaryDisplayName": "John Doe",
            "riskScore": score,
            "riskScoreSeverity": "HIGH",
            "riskFactors": [{"type": "EXPOSED_PASSWORD", "severity": "HIGH"}],
            "accounts": [{"domain": domain, "samAccountName": sam}],
        }

    def test_correlate_host_identity_full_flow(self):
        """Host, identity and matching detections are stitched together."""
        alerts = [
            {
                "composite_id": "c-1",
                "tactic": "Credential Access",
                "user_name": "JDOE",
                "created_timestamp": "2026-11-05T00:00:00Z",
                "display_name": "Kerberoasting",
            },
            {
                "composite_id": "c-2",
                "tactic": "",
                "user_name": "jdoe",
                "display_name": "Policy rule match",
            },
            {
                "composite_id": "c-3",
                "tactic": "Lateral Movement",
                "source_account_name": "CORP\\jdoe",
                "created_timestamp": "2026-11-06T00:00:00Z",
            },
            {"composite_id": "c-4", "tactic": "Discovery", "user_name": "someoneelse"},
        ]
        self.mock_client.command.side_effect = [
            self._host_response(),
            self._identity_response(
                [
                    self._entity("e-other", "OTHER.EXAMPLE.COM"),
                    self._entity("e-corp", "CORP.EXAMPLE.COM"),
                ]
            ),
            {
                "status_code": 200,
                "body": {
                    "resources": ["c-1", "c-2", "c-3", "c-4"],
                    "meta": {"pagination": {"total": 4}},
                },
            },
            {"status_code": 200, "body": {"resources": alerts}},
        ]

        result = self.module.correlate_host_identity(device_id=DEVICE_ID.upper())

        host_call, graphql_call, query_call, details_call = self.mock_client.command.call_args_list
        self.assertEqual(host_call.args[0], "PostDeviceDetailsV2")
        self.assertEqual(host_call.kwargs["body"], {"ids": [DEVICE_ID]})
        self.assertEqual(graphql_call.args[0], "api_preempt_proxy_post_graphql")
        query = graphql_call.kwargs["body"]["query"]
        self.assertIn('samAccountNames: ["jdoe"]', query)
        self.assertIn("types: [USER]", query)
        self.assertEqual(query_call.args[0], "GetQueriesAlertsV2")
        alert_filter = query_call.kwargs["parameters"]["filter"]
        self.assertTrue(alert_filter.startswith("product:'idp'+created_timestamp:>'"))
        self.assertIn("+status:['new','reopened','in_progress']", alert_filter)
        self.assertNotIn("jdoe", alert_filter)
        self.assertEqual(details_call.args[0], "PostEntitiesAlertsV2")
        self.assertEqual(
            details_call.kwargs["body"], {"composite_ids": ["c-1", "c-2", "c-3", "c-4"]}
        )

        self.assertEqual(
            result["host"],
            {
                "device_id": DEVICE_ID,
                "hostname": "WS-01",
                "machine_domain": "corp.example.com",
                "last_login_user": "jdoe",
                "last_login_timestamp": "2026-11-06T09:00:00Z",
                "platform_name": "Windows",
            },
        )
        self.assertEqual(result["identity"]["entityId"], "e-corp")
        self.assertEqual(result["identity_match"], "domain")
        self.assertEqual([d["composite_id"] for d in result["idp_detections"]], ["c-3", "c-1"])
        self.assertEqual(result["idp_detections_scan"]["scanned"], 4)
        self.assertEqual(result["idp_detections_scan"]["total"], 4)
        self.assertNotIn("identity_error", result)
        self.assertNotIn("idp_detections_error", result)

    def test_correlate_host_identity_options(self):
        """Policy matches and closed detections can be brought back in."""
        self.mock_client.command.side_effect = [
            self._host_response(machine_domain=None),
            self._identity_response([self._entity("e-1", "CORP.EXAMPLE.COM")]),
            {"status_code": 200, "body": {"resources": ["c-2"]}},
            {
                "status_code": 200,
                "body": {"resources": [{"composite_id": "c-2", "tactic": "", "user_name": "jdoe"}]},
            },
        ]

        result = self.module.correlate_host_identity(
            device_id=DEVICE_ID,
            detection_lookback_days=30,
            include_policy_matches=True,
            include_closed=True,
        )

        alert_filter = self.mock_client.command.call_args_list[2].kwargs["parameters"]["filter"]
        self.assertNotIn("status:", alert_filter)
        self.assertEqual(result["identity_match"], "account_name")
        self.assertEqual([d["composite_id"] for d in result["idp_detections"]], ["c-2"])

    def test_correlate_host_identity_batches_alert_details(self):
        """Alert details are fetched 100 composite IDs at a time."""
        ids = [f"c-{i}" for i in range(200)]

        def respond(operation, **kwargs):
            if operation == "PostDeviceDetailsV2":
                return self._host_response()
            if operation == "api_preempt_proxy_post_graphql":
                return self._identity_response([])
            if operation == "GetQueriesAlertsV2":
                self.assertEqual(kwargs["parameters"]["limit"], 200)
                return {"status_code": 200, "body": {"resources": ids}}
            batch = kwargs["body"]["composite_ids"]
            return {
                "status_code": 200,
                "body": {"resources": [{"composite_id": i, "tactic": "x"} for i in batch]},
            }

        self.mock_client.command.side_effect = respond

        result = self.module.correlate_host_identity(device_id=DEVICE_ID)

        detail_calls = [
            c
            for c in self.mock_client.command.call_args_list
            if c.args[0] == "PostEntitiesAlertsV2"
        ]
        self.assertEqual([len(c.kwargs["body"]["composite_ids"]) for c in detail_calls], [100, 100])
        self.assertEqual(result["idp_detections_scan"]["scanned"], 200)
        self.assertIsNone(result["identity"])
        self.assertEqual(result["identity_match"], "none")

    def test_correlate_host_identity_rejects_bad_device_ids(self):
        """Only a 32-character hex AID reaches the API."""
        hostile = [
            "",
            None,
            123,
            "0123456789abcdef0123456789abcde",
            "0123456789abcdef0123456789abcdef0",
            "0123456789abcdef0123456789abcdeg",
            "0123456789abcdef0123456789abcdef' OR '1'='1",
            '0123456789abcdef0123456789abcdef"}) { x }',
            "../../0123456789abcdef0123456789",
        ]
        for bad in hostile:
            with self.subTest(device_id=bad):
                result = self.module.correlate_host_identity(device_id=bad)
                self.assertIn("Invalid device_id", result[0]["error"])
        self.mock_client.command.assert_not_called()

    def test_correlate_host_identity_rejects_bad_lookback(self):
        for bad in [0, 91, "14", True]:
            with self.subTest(detection_lookback_days=bad):
                result = self.module.correlate_host_identity(
                    device_id=DEVICE_ID, detection_lookback_days=bad
                )
                self.assertIn("detection_lookback_days", result[0]["error"])
        self.mock_client.command.assert_not_called()

    def test_correlate_host_identity_hostile_login_user_stays_in_graphql_string(self):
        """A crafted last_login_user from the host record can't break out of the query."""
        payload = 'x"]) { nodes { entityId } } } mutation { evil } #'
        self.mock_client.command.side_effect = [
            self._host_response(last_login_user=payload),
            self._identity_response([]),
            {"status_code": 200, "body": {"resources": []}},
        ]

        result = self.module.correlate_host_identity(device_id=DEVICE_ID)

        query = self.mock_client.command.call_args_list[1].kwargs["body"]["query"]
        self.assertNotIn('x"])', query)
        self.assertIn('samAccountNames: ["x\\"]) { nodes', query)
        # The user name is matched client-side and never enters the alerts filter
        alert_filter = self.mock_client.command.call_args_list[2].kwargs["parameters"]["filter"]
        self.assertNotIn("x", alert_filter.replace("idp", ""))
        self.assertEqual(result["idp_detections"], [])

    def test_account_identity_builder_escapes_and_refuses_empty(self):
        query = self.module._build_account_identity_query('a"b\\c')
        self.assertIn('samAccountNames: ["a\\"b\\\\c"]', query)
        with self.assertRaises(ValueError):
            self.module._build_account_identity_query("")

    def test_correlate_host_identity_host_not_found(self):
        self.mock_client.command.return_value = {"status_code": 200, "body": {"resources": []}}

        result = self.module.correlate_host_identity(device_id=DEVICE_ID)

        self.assertIn("No host found", result[0]["error"])
        self.assertEqual(self.mock_client.command.call_count, 1)

    def test_correlate_host_identity_host_error(self):
        self.mock_client.command.return_value = {
            "status_code": 403,
            "body": {"errors": [{"message": "access denied"}]},
        }

        result = self.module.correlate_host_identity(device_id=DEVICE_ID)

        self.assertIn("error", result[0])
        self.assertEqual(self.mock_client.command.call_count, 1)

    def test_correlate_host_identity_no_login_user(self):
        """Without a logged-in user there is nothing to correlate, and no further calls."""
        self.mock_client.command.return_value = self._host_response(last_login_user=None)

        result = self.module.correlate_host_identity(device_id=DEVICE_ID)

        self.assertEqual(self.mock_client.command.call_count, 1)
        self.assertIsNone(result["identity"])
        self.assertEqual(result["idp_detections"], [])
        self.assertIn("note", result)

    def test_correlate_host_identity_partial_failures(self):
        """Identity and detection failures are reported without losing the host."""
        self.mock_client.command.side_effect = [
            self._host_response(),
            {
                "status_code": 200,
                "body": {"errors": [{"message": "Cannot query field"}], "data": None},
            },
            {"status_code": 403, "body": {"errors": [{"message": "access denied"}]}},
        ]

        result = self.module.correlate_host_identity(device_id=DEVICE_ID)

        self.assertEqual(result["host"]["hostname"], "WS-01")
        self.assertIsNone(result["identity"])
        self.assertIn("Cannot query field", result["identity_error"]["error"])
        self.assertIn("error", result["idp_detections_error"])
        self.assertEqual(result["idp_detections"], [])


if __name__ == "__main__":
    unittest.main()
