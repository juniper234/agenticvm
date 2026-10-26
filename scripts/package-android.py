"""Create a fresh native Linux + Android portable app; never replace a bundle."""
from pathlib import Path
import argparse
import json
import os
import runpy
import shutil
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from agenticvm.android import verify_assets, verify_helper, sha256


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--native-shell", type=Path, default=ROOT / "dist/AgenticVM-Android-shell")
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists():
        raise RuntimeError("Use a new bundle output directory; existing files are preserved")
    if output.parent != ROOT / "dist":
        raise RuntimeError("Portable output must be a fresh direct child of this repository's dist folder")
    verify_assets()
    helper = verify_helper()
    portable = runpy.run_path(str(ROOT / "scripts/package-portable.py"))
    python_directory, python_archive, python_verified = portable["prepare_python"](download=False)
    qemu_directory, qemu_files, qemu_spec = portable["verify_qemu"]()
    desktop_manifest, desktop_files = portable["verify_image_manifest"]("runtime/linux-desktop/build-manifest.json", desktop=True)
    command_manifest, command_files = portable["verify_image_manifest"]("runtime/linux-agent/build-manifest.json", desktop=False)
    peer_manifest, peer_files = portable["verify_image_manifest"]("runtime/linux-peer/build-manifest.json", desktop=False, peer=True)
    if peer_manifest["root_disk"]["sha256"] != desktop_manifest["root_disk"]["sha256"]:
        raise RuntimeError("Linux peer and desktop immutable roots differ")
    if shutil.disk_usage(output.parent).free < 8 * 1024**3:
        raise RuntimeError("Packaging needs 8 GiB free disk")
    native = args.native_shell.resolve()
    if not (native / "AgenticVM.exe").is_file():
        raise RuntimeError("Build the existing native shell before packaging Android")
    output.mkdir()
    for source in native.iterdir():
        if source.name == "bundle":
            continue
        if source.is_dir():
            shutil.copytree(source, output / source.name)
        else:
            shutil.copy2(source, output / source.name)
    bundle = output / "bundle"
    bundle.mkdir()
    (bundle / "python").mkdir()
    python_lock = portable["load"](ROOT / "tools/python-runtime-lock.json")
    with zipfile.ZipFile(python_archive) as archive:
        for entry in portable["zip_entries"](python_archive, python_lock):
            shutil.copy2(python_directory / entry.filename, bundle / "python" / entry.filename)
        pth = b"python313.zip\n.\n../src\n# Isolated AgenticVM portable runtime.\n"
        (bundle / "python/python313._pth").write_bytes(pth)
        for entry in portable["zip_entries"](python_archive, python_lock):
            expected = pth if entry.filename == "python313._pth" else archive.read(entry)
            if (bundle / "python" / entry.filename).read_bytes() != expected:
                raise RuntimeError("Relocated Python payload differs: " + entry.filename)
    shutil.copytree(ROOT / "src", bundle / "src", ignore=shutil.ignore_patterns("__pycache__"))
    (bundle / "desktop").mkdir()
    shutil.copy2(ROOT / "desktop/backend_host.py", bundle / "desktop/backend_host.py")
    for item in qemu_files:
        target = bundle / "tools/qemu/11.1.0" / item["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(qemu_directory / item["path"], target)
        if sha256(target) != item["sha256"]:
            raise RuntimeError("Copied QEMU dependency differs: " + item["path"])
    for source, relative in desktop_files + command_files + peer_files:
        target = bundle / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if not target.exists():
            shutil.copy2(source, target)
        if sha256(target) != sha256(source):
            raise RuntimeError("Copied Linux image/manifest differs: " + relative)
    for name in ("build-tools-lock.json", "desktop-image-lock.json", "python-runtime-lock.json"):
        shutil.copy2(ROOT / "tools" / name, bundle / "tools" / name)
    for manifest in (desktop_manifest, command_manifest, peer_manifest):
        if manifest.get("package_lock"):
            relative = manifest["package_lock"]
            target = bundle / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            if not target.exists():
                shutil.copy2(ROOT / relative, target)
    shutil.copytree(ROOT / "tools/android/sdk", bundle / "tools/android/sdk")
    shutil.copytree(ROOT / "tools/android/control", bundle / "tools/android/control", ignore=shutil.ignore_patterns("control-previous-*"))
    shutil.copy2(ROOT / "tools/android/prepared.json", bundle / "tools/android/prepared.json")
    shutil.copy2(ROOT / "tools/android-lock.json", bundle / "tools/android-lock.json")
    shutil.copytree(ROOT / "guest/android-control", bundle / "guest/android-control")
    shutil.copy2(ROOT / "docs/android-support.md", output / "ANDROID-README.md")
    for module, filename in (("agenticvm", "agenticvm.ps1"), ("agenticvm.mcp", "agenticvm-mcp.ps1")):
        wrapper = "$ErrorActionPreference = 'Stop'\n$bundleRoot = Join-Path $PSScriptRoot 'bundle'\n$controllerPython = Join-Path $bundleRoot 'python/python.exe'\nPush-Location -LiteralPath $bundleRoot\ntry { & $controllerPython -I -B -m " + module + " @args; $controllerExit = $LASTEXITCODE } finally { Pop-Location }\nexit $controllerExit\n"
        (output / filename).write_text(wrapper, encoding="utf-8")
    (output / "scripts").mkdir()
    shutil.copy2(ROOT / "scripts/open-android-app.py", output / "scripts/open-android-app.py")
    (output / "Start-AgenticVM.cmd").write_text('@echo off\r\n"%~dp0bundle\\python\\pythonw.exe" -I -B "%~dp0scripts\\open-android-app.py"\r\n', encoding="ascii")
    notices = ("Local Linux + Android development bundle. No external publication performed.\n"
               "Python: bundle/python/LICENSE.txt; original pinned CPython archive verified.\n"
               "QEMU: bundle/tools/qemu/11.1.0/COPYING and COPYING.LIB; pinned installed payload verified.\n"
               "Android Emulator and AOSP system image: NOTICE/license files retained under bundle/tools/android/sdk.\n"
               "Android control APK: first-party source under bundle/guest/android-control; public AOSP test signing key.\n"
               "Guest distribution package copyright/provenance remains in the immutable Linux root and build manifests.\n"
               "Native Windows shell contains its existing .NET/WebView2 redistributable runtime.\n")
    (output / "THIRD-PARTY-NOTICES.txt").write_text(notices, encoding="utf-8")
    environment = os.environ.copy()
    environment.pop("AGENTICVM_HOME", None)
    probe = subprocess.run([str(bundle / "python/python.exe"), "-I", "-B", "-m", "agenticvm", "--workspace", str(output / "runtime/package-probe"), "--backend", "android", "doctor"],
                           cwd=output, env=environment, capture_output=True, timeout=120, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    response = json.loads(probe.stdout)
    if probe.returncode or not response.get("ok"):
        raise RuntimeError("Relocated Android bundle probe failed: " + str(response))
    pins = {}
    for name in ("AgenticVM.exe", "bundle/python/python.exe", "bundle/src/agenticvm/android.py", "bundle/src/agenticvm/cli.py", "bundle/src/agenticvm/viewer.py", "bundle/src/agenticvm/mcp.py", "bundle/tools/android/control/control.apk", "bundle/tools/android/prepared.json"):
        pins[name] = sha256(output / name)
    receipt = {"schema": "agenticvm.android-portable.v1", "passed": True, "output": str(output), "pins": pins,
               "android": response["result"], "helper_sha256": helper,
               "python_verification": python_verified, "qemu_files_verified": len(qemu_files), "qemu_version": qemu_spec["version"],
               "linux_images_verified": [manifest.get("output") or manifest.get("iso") for manifest in (desktop_manifest, command_manifest, peer_manifest)],
               "native_shell": str(native), "native_source_pins": {name: sha256(ROOT / "desktop/AgenticVM.Desktop" / name) for name in ("Controls.cs", "MainForm.cs")},
               "bytes": sum(p.stat().st_size for p in output.rglob("*") if p.is_file()),
               "no_user_vm_data_copied": True, "no_host_settings_changed": True}
    (output / "android-package-receipt.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    main()
