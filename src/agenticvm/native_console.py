"""Decode bounded complete proof objects even when console status shares a line."""
import json


def json_records(text, marker):
    decoder, result = json.JSONDecoder(), []
    for line in text.splitlines():
        if marker not in line:
            continue
        raw = line.split(marker, 1)[1].lstrip()
        try:
            value, end = decoder.raw_decode(raw[:65537])
        except (ValueError, RecursionError):
            continue
        if end > 65536 or not isinstance(value, dict):
            continue
        # Kernel/systemd progress may begin between the JSON write and its
        # trailing newline. The complete JSON object is still independently
        # validated by the route's OS/scope/activation/fault verifier.
        result.append(value)
    return result
