"""Independently audit an Android native receipt without starting any VM."""
from pathlib import Path
import argparse
import hashlib
import json
import struct

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = {"native_boot", "shell_identity", "unsupported_bluetooth_disabled", "adb_identity_binding", "effective_persistent_disk_binding", "offline_network_denied", "native_screenshot", "apk_install", "invalid_apk_denied", "app_launch", "unicode_touch_input", "literal_argv",
            "binary_transfer_1mib", "path_escape_denied", "bounded_output", "guest_deadline", "host_alias_denied_offline", "android_home", "android_navigation",
            "clean_stop", "cold_boot", "persistent_app_data", "persistent_workspace", "host_control_denied_nat", "nat_default_network", "nat_outbound", "https_browser",
            "mcp_screenshot", "viewer_screen", "failed_boot_cleanup", "controller_crash_recovery", "source_pins_unchanged"}


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    args = parser.parse_args()
    path = args.report.resolve()
    report = json.loads(path.read_text(encoding="utf-8"))
    checks = []
    def record(name, value, **details):
        checks.append({"name": name, "passed": bool(value), **details})
    record("native_suite_complete", report.get("passed") and report.get("complete") and report.get("smoke_only") is False)
    rows = report.get("checks", [])
    names = [row["name"] for row in rows]
    record("required_assertions", REQUIRED <= set(names) and len(set(names)) == len(names) and all(row.get("passed") is True for row in rows), missing=sorted(REQUIRED - set(names)))
    pins = report.get("source_pins", {})
    changed = [name for name, expected in pins.items() if not (ROOT / name).resolve().is_relative_to(ROOT) or not (ROOT / name).is_file() or digest(ROOT / name) != expected]
    record("current_source_pins", len(pins) >= 15 and not changed, files=len(pins), changed=changed)
    broken = []
    for name, expected in report.get("artifacts", {}).items():
        artifact = path.parent / name
        if not artifact.resolve().is_relative_to(path.parent) or not artifact.is_file() or digest(artifact) != expected:
            broken.append(name)
    record("artifact_digests", len(report.get("artifacts", {})) >= 5 and not broken, broken=broken)
    png = path.parent / "boot.png"
    record("actual_display_dimensions", png.is_file() and png.read_bytes().startswith(b"\x89PNG\r\n\x1a\n") and struct.unpack(">II", png.read_bytes()[16:24]) == (720, 1280))
    import xml.etree.ElementTree as ET
    marker = "Android 中文 ✓ 😀 ' $ ; %s " + path.parent.name[:8]
    expected_text = "SHA256 " + hashlib.sha256(marker.encode()).hexdigest()
    persisted = path.parent / "persistent-app.xml"
    tree = ET.fromstring(persisted.read_bytes()) if persisted.is_file() else ET.Element("empty")
    record("persistent_unicode_ui_evidence", any(node.get("content-desc") == "agenticvm-status" and node.get("text") == expected_text for node in tree.iter("node")))
    browser = (path.parent / "browser.xml").read_bytes() if (path.parent / "browser.xml").is_file() else b""
    record("https_webview_ui_evidence", b"This domain is for use in documentation examples" in browser and b"https://example.com/" in browser and b"android.webkit.WebView" in browser)
    previous, valid, count = "0" * 64, True, 0
    for line in (path.parent / "checkpoints.jsonl").read_text(encoding="utf-8").splitlines():
        row = json.loads(line)
        expected = row.pop("checkpoint_sha256", None)
        calculated = hashlib.sha256(json.dumps(row, sort_keys=True, ensure_ascii=True).encode()).hexdigest()
        valid = valid and expected == calculated and row["previous"] == previous
        previous = expected
        count += 1
    record("checkpoint_hash_chain", valid and count >= len(REQUIRED), records=count)
    record("owned_process_cleanup", report.get("all_owned_processes_stopped") is True and not report.get("cleanup_error") and bool(report.get("cleanup")))
    record("test_controller_cleanup", report.get("test_controllers_stopped") is True and not report.get("controller_cleanup_error"))
    # Probe only creation/executable identities from the saved manifest. No stop,
    # network request, resource mutation, or inference is performed by this audit.
    import sys
    sys.path.insert(0, str(ROOT / "src"))
    from agenticvm.android import AndroidStore, owned_process
    from agenticvm.png_evidence import png_signal
    record("painted_display", png_signal(png.read_bytes())["nonblack_pixels"] >= 100)
    store = AndroidStore(path.parent / "workspace")
    state = store.load()
    live = []
    for pin in state["processes"] + ([state["launcher"]] if state.get("launcher") else []):
        with owned_process(pin) as process:
            if process.alive():
                live.append(pin)
    record("independent_liveness_probe", not state["registered"] and not live, live=live)
    result = {"schema": "agenticvm.android-independent-audit.v1", "passed": all(row["passed"] for row in checks),
              "receipt": str(path), "receipt_sha256": digest(path), "checks": checks}
    output = path.parent / "independent-audit.json"
    output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
