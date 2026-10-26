"""Build the first-party Android input helper; public AOSP test signing key only."""
from __future__ import annotations
import base64
import hashlib
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import urllib.request
from uuid import uuid4
import zipfile

ROOT = Path(__file__).resolve().parents[1]
prep = runpy.run_path(str(ROOT / "scripts/prepare-android.py"))
digest, fetch = prep["digest"], prep["fetch"]


def main():
    cache = ROOT / "downloads/android"
    dev = ROOT / "tools/android/build"
    cache.mkdir(parents=True, exist_ok=True)
    dev.mkdir(parents=True, exist_ok=True)
    specs = [
        {"name": "build-tools-35", "url": "https://dl.google.com/android/repository/build-tools_r35_windows.zip", "size": 59878107, "sha1": "af059bb67cf7786f45ee0db85e2d24985df1b4b6"},
        {"name": "platform-35", "url": "https://dl.google.com/android/repository/platform-35_r02.zip", "size": 64273788, "sha1": "0bb560a90a7a2cbd0dd8348224d518b638fe7949"}
    ]
    archives = []
    for spec in specs:
        item = fetch(spec, cache)
        archives.append(item)
        destination = dev / spec["name"]
        if not destination.exists():
            stage = dev / (".extract-" + str(uuid4()))
            stage.mkdir()
            with zipfile.ZipFile(item["archive"]) as archive:
                for member in archive.namelist():
                    if ".." in Path(member).parts or ":" in member or member.startswith("/") or "\\" in member:
                        raise ValueError("Unsafe SDK archive member")
                archive.extractall(stage)
            children = list(stage.iterdir())
            if len(children) != 1 or not children[0].is_dir():
                raise ValueError("Unexpected SDK archive layout")
            children[0].rename(destination)
    jdk = Path(os.environ.get("JAVA_HOME", "C:/Program Files/Java/jdk-24"))
    java, javac = jdk / "bin/java.exe", jdk / "bin/javac.exe"
    if not java.is_file() or not javac.is_file():
        raise RuntimeError("Set JAVA_HOME to an existing JDK; no JDK is installed by this script")
    folder = ROOT / "runtime/android-control-builds" / str(uuid4())
    folder.mkdir(parents=True)
    source = ROOT / "guest/android-control"
    buildtools, platform = dev / "build-tools-35", dev / "platform-35"
    android_jar = platform / "android.jar"
    def command(argv):
        result = subprocess.run(list(map(str, argv)), capture_output=True, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0), timeout=120)
        with (folder / "build.log").open("ab") as stream:
            stream.write(result.stdout + result.stderr)
        if result.returncode:
            raise RuntimeError(result.stderr.decode("utf-8", "replace")[-3000:])
    command([buildtools / "aapt2.exe", "compile", "--dir", source / "res", "-o", folder / "resources.zip"])
    command([buildtools / "aapt2.exe", "link", "-I", android_jar, "--manifest", source / "AndroidManifest.xml", "-o", folder / "base.apk", folder / "resources.zip"])
    classes = folder / "classes"
    classes.mkdir()
    command([javac, "-encoding", "UTF-8", "-source", "8", "-target", "8", "-classpath", android_jar, "-d", classes, *sorted(source.rglob("*.java"))])
    dex = folder / "dex"
    dex.mkdir()
    command([java, "-cp", buildtools / "lib/d8.jar", "com.android.tools.r8.D8", "--lib", android_jar, "--min-api", "26", "--output", dex, *sorted(classes.rglob("*.class"))])
    with zipfile.ZipFile(folder / "base.apk", "a") as archive:
        archive.write(dex / "classes.dex", "classes.dex")
    public_keys = []
    for name in ("testkey.pk8", "testkey.x509.pem"):
        url = "https://android.googlesource.com/platform/build/+/refs/tags/android-15.0.0_r1/target/product/security/" + name + "?format=TEXT"
        path = dev / name
        if not path.exists():
            with urllib.request.urlopen(url, timeout=60) as response:
                path.write_bytes(base64.b64decode(response.read()))
        public_keys.append({"url": url, "sha256": digest(path)})
    command([java, "-jar", buildtools / "lib/apksigner.jar", "sign", "--key", dev / "testkey.pk8", "--cert", dev / "testkey.x509.pem", "--out", folder / "control.apk", folder / "base.apk"])
    command([java, "-jar", buildtools / "lib/apksigner.jar", "verify", "--verbose", folder / "control.apk"])
    output = ROOT / "tools/android/control"
    output.mkdir(parents=True, exist_ok=True)
    target = output / "control.apk"
    if target.exists() and digest(target) != digest(folder / "control.apk"):
        backup = output / ("control-previous-" + str(uuid4()) + ".apk")
        shutil.copy2(target, backup)
    shutil.copy2(folder / "control.apk", target)
    receipt = {"schema": "agenticvm.android-control.v1", "apk_sha256": digest(target), "build": str(folder),
               "sources": {str(p.relative_to(ROOT)).replace("\\", "/"): digest(p) for p in sorted(source.rglob("*")) if p.is_file()},
               "archives": archives, "signing": "Public AOSP test key; not a secret or production signing identity", "public_signing_inputs": public_keys}
    (output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    main()
