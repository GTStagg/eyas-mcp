"""
Contains On-Demand Scan resources.
"""

ODS_FQL_DOCUMENTATION = """Falcon Query Language (FQL) - On-Demand Scans Guide

On-demand scans (ODS) scan files on chosen hosts for malware. Scans, their per-host
results, the malicious files they found and scheduled scans are searched with FQL.

=== BASIC SYNTAX ===
property_name:[operator]'value'

=== OPERATORS ===
• = (default): Equals
• !: Not equal
• >, >=, <, <=: Comparison (numbers and timestamps)

=== COMBINING ===
• + (AND): status:'completed'+filecount.malicious:>0
• , (OR): status:'running',status:'pending'

=== SCANS (falcon_search_ods_scans) ===
id, profile_id, description, description.keyword, initiated_from, status, severity,
filecount.scanned, filecount.malicious, filecount.quarantined, filecount.skipped,
affected_hosts_count, targeted_host_count, missing_host_count, targeted_platforms,
scan_started_on, scan_completed_on, created_on, created_by, last_updated.
Statuses seen: pending, running, completed, incomplete, canceled.
initiated_from seen: falcon_adhoc (started from the console or API), endpoint_user.
Ex: created_on:>'now-7d'+filecount.malicious:>0

=== SCAN HOSTS (falcon_search_ods_scan_hosts) ===
id, scan_id, host_id, host_scan_id, profile_id, status, severity, filecount.scanned,
filecount.malicious, filecount.quarantined, filecount.skipped, started_on,
completed_on, last_updated, scan_control_reason.
Ex: scan_id:'<scan id>'

=== MALICIOUS FILES (falcon_search_ods_malicious_files) ===
id, scan_id, host_id, host_scan_id, filepath, filename, hash, pattern_id, severity,
quarantined, last_updated.
Ex: scan_id:'<scan id>'+quarantined:false

=== SCHEDULED SCANS (falcon_search_ods_scheduled_scans) ===
id, description, description.keyword, initiated_from, status, schedule.start_timestamp,
schedule.Interval, created_on, created_by, last_updated, deleted, targeted_platforms.

=== SORT ===
field|asc or field|desc, e.g. created_on|desc. An unknown sort field is rejected with
the list of allowed ones.
"""
