"""Windows guest inference backend using the same reviewed request protocol."""
from __future__ import annotations
import ctypes
from ctypes import wintypes
import hashlib
import os
from pathlib import Path
import subprocess
import time
import urllib.request

import lfm_protocol
from lfm_protocol import MODEL_NAME, MODEL_SHA

BASE = Path(os.environ.get('ProgramData', 'C:/ProgramData')) / 'Garden'


class LocalLFM(lfm_protocol.LocalLFM):
    def start(self):
        if os.name != 'nt':
            raise RuntimeError('The Windows inference backend must run inside the Windows target VM')
        with (BASE / 'model.gguf').open('rb') as stream:
            if hashlib.file_digest(stream, 'sha256').hexdigest() != MODEL_SHA:
                raise ValueError('Installed Windows model weights changed')
        self.verified = True
        self.log = (BASE / 'peer/model.log').open('wb')
        self.argv = [str(BASE / 'llama/llama-server.exe'), '-m', str(BASE / 'model.gguf'),
            '-c', '1024', '-t', '1', '-tb', '1', '-b', '64', '-ub', '64', '-np', '1', '-ngl', '0',
            '--host', '127.0.0.1', '--port', '8080', '--jinja', '--no-webui', '--no-warmup',
            '--fit', 'off', '--threads-http', '1']
        self.process = subprocess.Popen(self.argv, stdin=subprocess.DEVNULL, stdout=self.log, stderr=subprocess.STDOUT,
            env={**os.environ, 'LLAMA_ARG_REPACK': '0', 'OMP_NUM_THREADS': '1', 'OPENBLAS_NUM_THREADS': '1'},
            creationflags=subprocess.CREATE_NO_WINDOW)
        deadline = time.monotonic() + 150
        while time.monotonic() < deadline:
            self.ensure_alive()
            try:
                with urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=1) as response:
                    if response.status == 200 and response.headers.get_content_type() == 'application/json':
                        self.ready = True
                        return
            except OSError:
                time.sleep(.25)
        raise TimeoutError('Windows target model startup exceeded its bound')

    def ensure_alive(self):
        if self.process and self.process.poll() is not None:
            tail = (BASE / 'peer/model.log').read_text(errors='replace')[-1800:]
            raise RuntimeError('Windows target inference exited: ' + str(self.process.returncode) + '; ' + tail)

    def snapshot(self):
        self.ensure_alive()
        executable, memory = None, {}
        if self.process:
            handle = wintypes.HANDLE(int(self.process._handle))
            kernel = ctypes.WinDLL('kernel32', use_last_error=True)
            kernel.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
            kernel.QueryFullProcessImageNameW.restype = wintypes.BOOL
            buffer, count = ctypes.create_unicode_buffer(32768), wintypes.DWORD(32768)
            if not kernel.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(count)):
                raise OSError('Cannot inspect owned Windows inference executable')
            executable = buffer.value
            expected = str(BASE / 'llama' / 'llama-server.exe')
            if os.path.normcase(os.path.abspath(executable)) != os.path.normcase(os.path.abspath(expected)):
                raise RuntimeError('Windows inference executable is not the installed llama-server')
            class Counters(ctypes.Structure):
                _fields_ = [('cb', wintypes.DWORD), ('PageFaultCount', wintypes.DWORD),
                    *[(name, ctypes.c_size_t) for name in ('PeakWorkingSetSize', 'WorkingSetSize',
                        'QuotaPeakPagedPoolUsage', 'QuotaPagedPoolUsage', 'QuotaPeakNonPagedPoolUsage',
                        'QuotaNonPagedPoolUsage', 'PagefileUsage', 'PeakPagefileUsage', 'PrivateUsage')]]
            psapi = ctypes.WinDLL('psapi', use_last_error=True)
            psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(Counters), wintypes.DWORD]
            psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
            counters = Counters()
            counters.cb = ctypes.sizeof(counters)
            if not psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), ctypes.sizeof(counters)):
                raise OSError('Cannot inspect owned Windows inference memory')
            memory = {'working_set_bytes': counters.WorkingSetSize, 'peak_working_set_bytes': counters.PeakWorkingSetSize,
                      'private_bytes': counters.PrivateUsage}
        return {'name': MODEL_NAME, 'weights_sha256': MODEL_SHA, 'weights_verified_inside_vm': self.verified,
            'ready': self.ready, 'server_pid': self.process.pid if self.process else None,
            'server_alive': bool(self.process and self.process.poll() is None), 'cpu_threads': 1,
            'context_tokens': 1024, 'gpu': False, 'calls_started': self.calls,
            'server_memory': memory, 'execution_location': 'Windows guest', 'executable': executable,
            'argv': getattr(self, 'argv', []), 'http_scope': '127.0.0.1 inference API inside this VM only'}
