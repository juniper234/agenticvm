"""Read-only Windows counters for exact owned QEMU processes."""
import ctypes,time
from ctypes import wintypes
from .qemu import WindowsProcess

class MemoryCounters(ctypes.Structure):
    _fields_=[('cb',wintypes.DWORD),('faults',wintypes.DWORD),
        *[(name,ctypes.c_size_t) for name in ('peak_working_set','working_set','peak_paged_pool','paged_pool',
            'peak_nonpaged_pool','nonpaged_pool','pagefile','peak_pagefile','private_usage')]]

class ResourceTracker:
    def __init__(self):
        self.start=time.monotonic();self.samples=0;self.peaks={};self.total_working_set_peak=0;self.total_private_peak=0
    def sample(self,machines):
        api=ctypes.WinDLL('kernel32',use_last_error=True)
        api.K32GetProcessMemoryInfo.argtypes=[wintypes.HANDLE,ctypes.POINTER(MemoryCounters),wintypes.DWORD]
        api.K32GetProcessMemoryInfo.restype=wintypes.BOOL
        total=private=0
        for vm in machines:
            if not vm.binding: continue
            with WindowsProcess(vm.binding['pid']) as p:
                if not p.alive() or p.created!=vm.binding['created'] or str(p.executable)!=vm.binding['executable']:
                    raise ValueError('Cannot sample a changed/exited owned process')
                counters=MemoryCounters();counters.cb=ctypes.sizeof(counters)
                if not api.K32GetProcessMemoryInfo(p.handle,ctypes.byref(counters),counters.cb):
                    raise OSError(ctypes.get_last_error(),'Owned VM memory counter unavailable')
                created,exited,kernel,user=(wintypes.FILETIME() for _ in range(4))
                if not p.api.GetProcessTimes(p.handle,*map(ctypes.byref,(created,exited,kernel,user))):
                    raise OSError(ctypes.get_last_error(),'Owned VM CPU counter unavailable')
                cpu=((kernel.dwHighDateTime<<32)+kernel.dwLowDateTime+(user.dwHighDateTime<<32)+user.dwLowDateTime)/10**7
                name=vm.folder.name;old=self.peaks.setdefault(name,{'working_set_bytes':0,'private_bytes':0,'cpu_seconds':0})
                old.update(working_set_bytes=max(old['working_set_bytes'],counters.working_set),
                    private_bytes=max(old['private_bytes'],counters.private_usage),cpu_seconds=round(cpu,3))
                total+=counters.working_set;private+=counters.private_usage
        self.samples+=1;self.total_working_set_peak=max(self.total_working_set_peak,total)
        self.total_private_peak=max(self.total_private_peak,private)
    def report(self):
        return {'samples':self.samples,'observed_seconds':round(time.monotonic()-self.start,3),'processes':self.peaks,
            'peak_simultaneous_sum_working_set_bytes':self.total_working_set_peak,
            'peak_simultaneous_sum_private_bytes':self.total_private_peak,
            'actual_4gb_host_test':False,'note':'Process counter sums; shared pages can be counted more than once. Host OS and other applications excluded.'}
