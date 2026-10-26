"""Reclaim only already-zero ranges of the stopped, owned Windows test disk.

No disk bytes change. An exclusive handle and lifecycle lock prevent concurrent
use. This is a local maintenance script, not an agent-accessible filesystem API.
"""
import ctypes
from ctypes import wintypes
import hashlib
import json
import msvcrt
import os
from pathlib import Path
import shutil
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
os.environ.setdefault('AGENTICVM_SOCKET_ROOT',str(ROOT/'runtime/ipc'))
from agenticvm.windows_desktop import WindowsDesktopStore,WindowsDesktopBackend
from agenticvm.control_store import checked,save_json


def main():
    store=WindowsDesktopStore(ROOT/'runtime/glass-app/workspace','desktop-app-windows')
    backend=WindowsDesktopBackend(store)
    report={'operation':'reclaim verified zero ranges','started_at':time.time(),'ok':False,
        'compression_hash_verification_completed':False,'native_cold_boot_required':True}
    receipt=ROOT/'runtime/agent-control-development/zero-reclaim.json'
    save_json(receipt,report)
    with store.lock():
        state=store.load()
        assert not state['registered'] and backend.status()['registered'] is False
        path=checked(Path(state['disk']),store.root)
        expected=store.root/'windows-data/desktop-app-windows/system.qcow2'
        assert path==expected
        api=ctypes.WinDLL('kernel32',use_last_error=True)
        api.CreateFileW.argtypes=[wintypes.LPCWSTR,wintypes.DWORD,wintypes.DWORD,ctypes.c_void_p,wintypes.DWORD,wintypes.DWORD,wintypes.HANDLE]
        api.CreateFileW.restype=wintypes.HANDLE
        api.DeviceIoControl.argtypes=[wintypes.HANDLE,wintypes.DWORD,ctypes.c_void_p,wintypes.DWORD,ctypes.c_void_p,wintypes.DWORD,ctypes.POINTER(wintypes.DWORD),ctypes.c_void_p]
        handle=api.CreateFileW(str(path),0xC0000000,0,None,3,0,None)
        if handle==ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        class Range(ctypes.Structure):
            _fields_=[('start',ctypes.c_longlong),('end',ctypes.c_longlong)]
        changed=ranges=0
        before=hashlib.sha256()
        zero=b'\0'*65536
        free_before=shutil.disk_usage(ROOT).free
        with os.fdopen(msvcrt.open_osfhandle(handle,os.O_RDWR|os.O_BINARY),'r+b',buffering=0) as stream:
            size=os.fstat(stream.fileno()).st_size
            offset=0
            while block:=stream.read(1024*1024):
                before.update(block)
                for relative in range(0,len(block),65536):
                    part=block[relative:relative+65536]
                    if len(part)==65536 and part==zero:
                        span=Range(offset+relative,offset+relative+65536)
                        written=wintypes.DWORD()
                        if not api.DeviceIoControl(handle,0x980c8,ctypes.byref(span),ctypes.sizeof(span),None,0,ctypes.byref(written),None):
                            raise ctypes.WinError(ctypes.get_last_error())
                        changed+=65536
                        ranges+=1
                offset+=len(block)
                if offset%(1024**3)==0:
                    print(json.dumps({'scanned_gib':offset//1024**3,'zero_bytes':changed,'free_bytes':shutil.disk_usage(ROOT).free}),flush=True)
            stream.seek(0)
            after=hashlib.file_digest(stream,'sha256').hexdigest()
            assert before.hexdigest()==after and os.fstat(stream.fileno()).st_size==size
        report.update(ok=True,sha256=after,logical_bytes=size,zero_ranges=ranges,zero_bytes=changed,
            zero_reclaim_hash_unchanged=True,free_before=free_before,free_after=shutil.disk_usage(ROOT).free,finished_at=time.time())
        save_json(receipt,report)
        print(json.dumps(report),flush=True)


if __name__=='__main__':
    main()
