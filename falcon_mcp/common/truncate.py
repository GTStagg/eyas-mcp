"""
Bound the size of long text in API records.

Some Falcon endpoints return whole documents, such as a finished-intelligence
report body or a hunting guide written in Markdown. One record can be large
enough to crowd out the rest of a client's context, so tools that return them
clip each long string and say so in the text itself.
"""

from typing import Any

TRUNCATION_MARKER = (
    "\n\n[truncated: {remaining} more characters. Raise max_text_chars to read more.]"
)


def clip_long_strings(value: Any, max_chars: int) -> Any:
    """Return a copy of `value` with every string longer than `max_chars` clipped.

    Walks nested dicts and lists. A clipped string ends with a marker giving the
    number of characters left out, so a reader can tell clipped text from short
    text. Dict keys, numbers, booleans and None pass through unchanged.

    Args:
        value: An API record, list of records, or scalar
        max_chars: The longest string kept whole

    Returns:
        The clipped copy. The input is not modified.
    """
    if isinstance(value, str):
        if len(value) <= max_chars:
            return value
        return value[:max_chars] + TRUNCATION_MARKER.format(remaining=len(value) - max_chars)
    if isinstance(value, dict):
        return {key: clip_long_strings(item, max_chars) for key, item in value.items()}
    if isinstance(value, list):
        return [clip_long_strings(item, max_chars) for item in value]
    return value
