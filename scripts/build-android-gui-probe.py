"""Build an independent GUI install fixture using the already prepared tools."""
from pathlib import Path
import hashlib
import json
import subprocess
from uuid import uuid4
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    source = ROOT / "guest/android-gui-probe"
    dev = ROOT / "tools/android/build"
    buildtools = dev / "build-tools-35"
    android = dev / "platform-35/android.jar"
    java = Path("C:/Program Files/Java/jdk-24/bin")
    control_receipt = json.loads((ROOT / "tools/android/control/receipt.json").read_text(encoding="utf-8"))
    for item in control_receipt["public_signing_inputs"]:
        filename = item["url"].split("/")[-1].split("?")[0]
        if digest(dev / filename) != item["sha256"]:
            raise RuntimeError("Public test signing input changed")
    folder = ROOT / "runtime/android-gui-probe-builds" / str(uuid4())
    folder.mkdir(parents=True)
    commands = []
    def command(argv):
        argv = list(map(str, argv))
        result = subprocess.run(argv, capture_output=True, timeout=120,
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        commands.append({"argv": argv, "exit_code": result.returncode})
        with (folder / "build.log").open("ab") as log:
            log.write(result.stdout + result.stderr)
        if result.returncode:
            raise RuntimeError(result.stderr.decode("utf-8", "replace"))
    command([buildtools / "aapt2.exe", "link", "-I", android, "--manifest", source / "AndroidManifest.xml", "-o", folder / "base.apk"])
    classes, dex = folder / "classes", folder / "dex"
    classes.mkdir()
    dex.mkdir()
    command([java / "javac.exe", "-encoding", "UTF-8", "-source", "8", "-target", "8", "-classpath", android, "-d", classes, *sorted(source.rglob("*.java"))])
    command([java / "java.exe", "-cp", buildtools / "lib/d8.jar", "com.android.tools.r8.D8", "--lib", android, "--min-api", "26", "--output", dex, *sorted(classes.rglob("*.class"))])
    with zipfile.ZipFile(folder / "base.apk", "a") as archive:
        archive.write(dex / "classes.dex", "classes.dex")
    apk = folder / "GUI Install Probe.apk"
    command([java / "java.exe", "-jar", buildtools / "lib/apksigner.jar", "sign", "--key", dev / "testkey.pk8", "--cert", dev / "testkey.x509.pem", "--out", apk, folder / "base.apk"])
    command([java / "java.exe", "-jar", buildtools / "lib/apksigner.jar", "verify", "--verbose", apk])
    bad = folder / "Invalid GUI Probe.apk"
    bad.write_bytes(b"AgenticVM deliberate invalid APK fixture\n")
    receipt = {"schema": "agenticvm.android-gui-probe-build.v1", "apk": str(apk), "apk_sha256": digest(apk),
               "invalid_apk": str(bad), "invalid_apk_sha256": digest(bad), "package": "org.agenticvm.guiprobe",
               "sources": {str(p.relative_to(ROOT)).replace("\\", "/"): digest(p) for p in sorted(source.rglob("*")) if p.is_file()},
               "tools": {str(p): digest(p) for p in [java / "java.exe", java / "javac.exe", android, buildtools / "aapt2.exe", buildtools / "lib/d8.jar", buildtools / "lib/apksigner.jar"]},
               "signing": "Existing public AOSP test key; no new credentials", "commands": commands}
    (folder / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"receipt": str(folder / "receipt.json"), "apk": str(apk), "sha256": digest(apk)}))


if __name__ == "__main__":
    main()
