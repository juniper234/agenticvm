"""Read official evaluation WIM metadata and signed Setup without mounting it."""
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from agenticvm.lan_lab import digest, save


def image_metadata(path):
    api = ctypes.WinDLL('wimgapi', use_last_error=True)
    api.WIMCreateFile.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    api.WIMCreateFile.restype = wintypes.HANDLE
    api.WIMGetImageCount.argtypes = [wintypes.HANDLE]
    api.WIMGetImageCount.restype = wintypes.DWORD
    api.WIMGetImageInformation.argtypes = [wintypes.HANDLE, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.DWORD)]
    api.WIMGetImageInformation.restype = wintypes.BOOL
    api.WIMCloseHandle.argtypes = [wintypes.HANDLE]
    api.WIMCloseHandle.restype = wintypes.BOOL
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    created = wintypes.DWORD()
    handle = api.WIMCreateFile(str(path), 0x80000000, 3, 0, 0, ctypes.byref(created))
    if not handle or handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    result = []
    try:
        count = api.WIMGetImageCount(handle)
        if not 1 <= count <= 16:
            raise ValueError('Unexpected evaluation image count')
        pointer, size = ctypes.c_void_p(), wintypes.DWORD()
        try:
            # A WIM file handle is accepted directly. Reading its XML avoids
            # loading image resources or requiring a system temporary path.
            if not api.WIMGetImageInformation(handle, ctypes.byref(pointer), ctypes.byref(size)) or size.value > 1024**2:
                raise ctypes.WinError(ctypes.get_last_error())
            raw = ctypes.wstring_at(pointer, size.value // 2).lstrip('\ufeff').rstrip('\x00')
            root = ET.fromstring(raw)
            images = [root] if root.tag == 'IMAGE' else root.findall('IMAGE')
            if len(images) != count:
                raise ValueError('WIM metadata image count mismatch')
            for image in images:
                result.append({'index': int(image.attrib['INDEX']), 'name': image.findtext('NAME'), 'flags': image.findtext('FLAGS'),
                    'edition': image.findtext('WINDOWS/EDITIONID'), 'installation_type': image.findtext('WINDOWS/INSTALLATIONTYPE'),
                    'architecture': image.findtext('WINDOWS/ARCH'), 'build': image.findtext('WINDOWS/VERSION/BUILD')})
        finally:
            if pointer:
                kernel.LocalFree(pointer)
    finally:
        api.WIMCloseHandle(handle)
    return result


def main():
    downloaded = json.loads((ROOT / 'runtime/enrollment-images/windows-evaluation-download.json').read_text())
    source = ROOT / downloaded['path']
    if digest(source) != downloaded['sha256']:
        raise ValueError('Locally pinned official evaluation ISO changed')
    folder = ROOT / 'runtime/enrollment-images/windows-installer'
    folder.mkdir(exist_ok=True)
    manifest = folder / 'manifest.json'
    if manifest.exists():
        return print(json.dumps({'ready': True, 'manifest': str(manifest), 'native_acceptance': False}))
    seven = ROOT / 'tools/7zip/26.04/7z.exe'
    print('Extracting only signed Setup and install.wim for read-only native metadata inspection', flush=True)
    child = subprocess.run([str(seven), 'e', '-y', str(source), 'setup.exe', 'sources/install.wim', '-o' + str(folder)],
        capture_output=True, text=True, timeout=600)
    if child.returncode or not (folder / 'install.wim').exists() or not (folder / 'setup.exe').exists():
        raise RuntimeError('Evaluation metadata extraction failed: ' + child.stdout[-800:])
    path = str(folder / 'setup.exe').replace("'", "''")
    script = "$s=Get-AuthenticodeSignature -LiteralPath '" + path + "'; @{status=$s.Status.ToString(); subject=$s.SignerCertificate.Subject; thumbprint=$s.SignerCertificate.Thumbprint} | ConvertTo-Json -Compress"
    child = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', script],
        capture_output=True, text=True, timeout=60, creationflags=subprocess.CREATE_NO_WINDOW,
        env={**os.environ, 'PSModulePath': str(Path(os.environ['SystemRoot']) / 'System32/WindowsPowerShell/v1.0/Modules')})
    if child.returncode or not child.stdout.strip():
        raise RuntimeError('Microsoft signature probe failed (' + str(child.returncode) + '): ' + child.stderr[-1200:])
    signed = json.loads(child.stdout)
    if child.returncode or signed['status'] != 'Valid' or 'O=Microsoft Corporation' not in signed['subject']:
        raise ValueError('Microsoft Setup Authenticode publisher verification failed')
    images = image_metadata(folder / 'install.wim')
    candidates = [image for image in images if image['installation_type'] == 'Server Core' and 'Standard' in image['edition']]
    if len(candidates) != 1:
        raise ValueError('Expected one explicitly identified Standard evaluation Server Core image')
    pin = digest(folder / 'install.wim')
    save(manifest, {'iso': downloaded, 'images': images, 'selected_image': candidates[0],
        'setup_authenticode': signed, 'setup_sha256': digest(folder / 'setup.exe'), 'install_wim_sha256': pin,
        'inspection': 'Windows WIMGAPI read-only image metadata; no mount or host installation',
        'native_acceptance': False, 'extracted_wim_cache_retained': False})
    # This exact file was just extracted and hashed here. The immutable ISO
    # remains its recovery source; no user file or mounted image is removed.
    path = (folder / 'install.wim').resolve()
    if path.parent != folder.resolve() or path.name != 'install.wim':
        raise ValueError('Unexpected derived WIM cache path')
    path.unlink()
    print(json.dumps({'ready': True, 'selected_image': candidates[0], 'setup_authenticode': signed,
        'native_acceptance': False, 'manifest': str(manifest)}, indent=2))


if __name__ == '__main__':
    main()
