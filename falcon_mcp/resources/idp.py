"""
Contains Identity Protection resources.
"""

SEARCH_IDP_SENSORS_FQL_DOCUMENTATION = """Falcon Query Language (FQL) - Search Identity Protection Sensors Guide

=== BASIC SYNTAX ===
property_name:[operator]'value'

=== COMBINING ===
+ = AND, , = OR. Quote string values. Use * for wildcards in string matches.

=== COMMON FIELDS ===
- hostname: The sensor host's name, e.g. hostname:'DC01*'
- machine_domain: The Active Directory domain the host belongs to, e.g. machine_domain:'corp.example.com'
- status: The sensor's protection status, e.g. status:'Protected'
- agent_version: The installed sensor version
- os_version: The host's operating system version

These fields come from the sensor records the API returns. CrowdStrike does not
publish a full field list for this endpoint, so when a filter is rejected, run the
tool without a filter and use field names from a returned record.

=== SORTING ===
Sort by a field and direction with a dot, e.g. hostname.asc or status.desc.

=== EXAMPLES ===
- Domain controllers by name: hostname:'DC*'
- One domain: machine_domain:'corp.example.com'
- Sensors that are not protected: status:!'Protected'
"""
