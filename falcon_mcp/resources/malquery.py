"""
Contains MalQuery resources.
"""

from falcon_mcp.common.utils import generate_md_table

# Pattern types accepted by MalQuery exact search: (name, description, example)
MALQUERY_PATTERN_TYPES = [
    ("Type", "Description", "Example"),
    (
        "ascii",
        "Exact ASCII (single-byte) string. Start here for strings such as hostnames, PDB paths or mutex names.",
        "evil-c2.example.com",
    ),
    (
        "wide",
        "Exact UTF-16LE string. Try this when an ascii search finds nothing, since .NET and many Windows "
        "binaries store strings as UTF-16.",
        "AsyncRAT",
    ),
    (
        "hex",
        "Byte sequence written as an even number of hex characters, with no spaces or 0x prefix.",
        "4d5a90000300",
    ),
]

# Metadata fields MalQuery can return for each match: (name, description)
MALQUERY_FILTER_META_FIELDS = [
    ("Field", "Description"),
    ("sha256", "SHA-256 of the matching sample"),
    ("md5", "MD5 of the matching sample"),
    ("type", "File type, such as pe32 or elf64"),
    ("size", "File size in bytes"),
    ("first_seen", "When MalQuery first indexed the sample"),
    ("label", "Verdict label, such as malware or clean"),
    ("family", "Malware family name, when known"),
]

MALQUERY_EXACT_SEARCH_GUIDE = (
    """# MalQuery Exact Search Guide

MalQuery is CrowdStrike's index of malware and clean files. An exact search finds
samples that contain a byte-level match for a string or hex pattern. It searches
CrowdStrike's corpus, not your hosts, and it doesn't change anything in your tenant.

## Workflow

1. Optionally call `falcon_get_malquery_quotas` to check how many searches the
   tenant has left. Every exact search counts against the MalQuery quota.
2. Call `falcon_start_malquery_exact_search` with a distinctive pattern. It
   returns a `request_id` right away; the search runs asynchronously.
3. Call `falcon_get_malquery_request` with that `request_id` until `status` is
   `done` (or `failed`). Matches are in `results`.

Good patterns are specific to one family or campaign: a hardcoded C2 domain, a PDB
path, a mutex or service name, a unique user agent, or a byte sequence from a
decoder stub. Short or common strings return noise and use quota.

`falcon_get_malquery_file_metadata` returns what MalQuery knows about a hash you
already have, such as its family, label and first-seen date. Those values often make
good patterns for finding related samples.

## Pattern types

"""
    + generate_md_table(MALQUERY_PATTERN_TYPES)
    + """

## Options

- `limit`: maximum number of matching samples to return (1-1000, default 100).
- `filter_filetypes`: only match these file types, such as `pe32`, `pe64`, `elf64`,
  `macho`, `dalvik`, `doc`, `pdf`, `lnk`, `email`.
- `filter_meta`: metadata fields to include for each match (see below).
- `min_date` / `max_date`: limit matches by first-seen date, written `YYYY/MM/DD`.
- `min_size` / `max_size`: limit matches by file size, written as bytes or with a
  `KB`, `MB` or `GB` suffix, such as `500KB` or `3MB`.

## Metadata fields

"""
    + generate_md_table(MALQUERY_FILTER_META_FIELDS)
)
