"""Debian bootstrap dependency and archive regressions (no network)."""
import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("debian_packages", ROOT / "scripts/desktop-image-debian.py")
DEBIAN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DEBIAN)


def record(name, version="1", repository="trixie", **fields):
    return {"Package": name, "Version": version, "Architecture": "amd64", "repository": repository, **fields}


class DebianPackageTests(unittest.TestCase):
    def test_debian_version_order_handles_epochs_tildes_and_numeric_runs(self):
        for lower, higher in [("1~rc1", "1"), ("1.9", "1.10"), ("1", "1-1"),
                              ("1-1", "1-1+b1"), ("9.0", "1:1.0"),
                              ("153.5.0esr-1~deb13u1", "153.5.0esr-1")]:
            self.assertLess(DEBIAN.version_compare(lower, higher), 0)
            self.assertGreater(DEBIAN.version_compare(higher, lower), 0)
        self.assertEqual(DEBIAN.version_compare("1.001", "1.1"), 0)
        self.assertEqual(DEBIAN.version_compare("1", "1-0"), 0)

    def test_predepends_versioned_virtual_provider_and_alternative(self):
        records = [record("app", **{"Pre-Depends": "runtime (>= 2)", "Depends": "absent | bus (= 3)"}),
                   record("runtime", "1"), record("runtime", "2", "trixie-security"),
                   record("bus-provider", "7", Provides="bus (= 3)")]
        chosen, _ = DEBIAN.resolve(records, ["app"])
        self.assertEqual(chosen["runtime"]["Version"], "2")
        self.assertIn("bus-provider", chosen)

    def test_unversioned_virtual_provider_cannot_satisfy_versioned_dependency(self):
        with self.assertRaisesRegex(ValueError, "Unsatisfied"):
            DEBIAN.resolve([record("app", Depends="bus (>= 2)"), record("provider", Provides="bus")], ["app"])

    def test_essential_is_included_and_recommends_ignored(self):
        chosen, essentials = DEBIAN.resolve([record("app", Recommends="systemd-sysv"),
                                             record("base", Essential="yes")], ["app"])
        self.assertEqual(set(chosen), {"app", "base"})
        self.assertEqual(essentials, ["base"])

    def test_security_version_selected_and_exact_conflicts_fail(self):
        records = [record("app", Depends="library (= 2)"), record("library", "1"),
                   record("library", "2", "trixie-security")]
        chosen, _ = DEBIAN.resolve(records, ["app"])
        self.assertEqual(chosen["library"]["repository"], "trixie-security")
        records.append(record("other", Depends="library (= 1)"))
        with self.assertRaisesRegex(ValueError, "conflicting"):
            DEBIAN.resolve(records, ["app", "other"])

    def test_deb_ar_payload_preserves_tar_and_odd_member_padding(self):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w:xz") as archive:
            member = tarfile.TarInfo("./usr/share/example")
            member.size = 5
            archive.addfile(member, io.BytesIO(b"hello"))
        payload = stream.getvalue()

        def member(name, content):
            header = (name + "/").ljust(16) + "0".ljust(12) + "0".ljust(6) + "0".ljust(6) + "100644".ljust(8) + str(len(content)).ljust(10) + "`\n"
            return header.encode("ascii") + content + (b"\n" if len(content) % 2 else b"")

        data = b"!<arch>\n" + member("debian-binary", b"2.0\n") + member("control.tar.xz", b"odd") + member("data.tar.xz", payload)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "example.deb"
            path.write_bytes(data)
            self.assertEqual(DEBIAN.package_payload(path), payload)
            files = [(info.name, content.read()) for info, content in DEBIAN.package_members(path)]
            self.assertEqual(files, [("./usr/share/example", b"hello")])
            path.write_bytes(data[:-100])
            with self.assertRaisesRegex(ValueError, "Truncated"):
                DEBIAN.package_payload(path)


if __name__ == "__main__":
    unittest.main()
