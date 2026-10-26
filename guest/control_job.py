"""Durable job runner. Executed only inside the Linux/Windows guest."""
import base64
import ctypes
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time

LIMIT=65536


def save(path,value):
    temp=path.with_suffix('.tmp')
    with temp.open('w',encoding='utf-8') as stream:
        json.dump(value,stream); stream.flush(); os.fsync(stream.fileno())
    os.replace(temp,path)


def drain(pipe,path):
    kept=0
    with path.open('wb',buffering=0) as output:
        while data:=pipe.read(4096):
            chunk=data[:max(0,LIMIT-kept)]
            output.write(chunk); kept+=len(chunk)
            if len(chunk)<len(data):
                path.with_suffix('.truncated').touch()


class WindowsTree:
    """Assign a suspended child before it can create any descendants."""
    def __init__(self,child):
        from ctypes import wintypes as w
        class IO(ctypes.Structure):
            _fields_=[(n,ctypes.c_ulonglong) for n in ('r','w','o','rb','wb','ob')]
        class BASIC(ctypes.Structure):
            _fields_=[('process_time',ctypes.c_longlong),('job_time',ctypes.c_longlong),('flags',w.DWORD),
                ('minimum',ctypes.c_size_t),('maximum',ctypes.c_size_t),('active',w.DWORD),('affinity',ctypes.c_size_t),('priority',w.DWORD),('scheduling',w.DWORD)]
        class EXT(ctypes.Structure):
            _fields_=[('basic',BASIC),('io',IO),('process_memory',ctypes.c_size_t),('job_memory',ctypes.c_size_t),('peak_process',ctypes.c_size_t),('peak_job',ctypes.c_size_t)]
        k=ctypes.WinDLL('kernel32',use_last_error=True)
        k.CreateJobObjectW.argtypes=[ctypes.c_void_p,w.LPCWSTR]; k.CreateJobObjectW.restype=w.HANDLE
        k.SetInformationJobObject.argtypes=[w.HANDLE,ctypes.c_int,ctypes.c_void_p,w.DWORD]
        k.AssignProcessToJobObject.argtypes=[w.HANDLE,w.HANDLE]
        k.TerminateJobObject.argtypes=[w.HANDLE,w.UINT]
        k.CloseHandle.argtypes=[w.HANDLE]
        self.api=k; self.handle=k.CreateJobObjectW(None,None)
        info=EXT(); info.basic.flags=0x2000 # KILL_ON_JOB_CLOSE
        if not self.handle or not k.SetInformationJobObject(self.handle,9,ctypes.byref(info),ctypes.sizeof(info)) or not k.AssignProcessToJobObject(self.handle,int(child._handle)):
            child.kill(); child.wait(); self.close(); raise OSError('Cannot own job process tree')
        n=ctypes.WinDLL('ntdll'); n.NtResumeProcess.argtypes=[w.HANDLE]; n.NtResumeProcess.restype=ctypes.c_long
        if n.NtResumeProcess(int(child._handle))!=0:
            self.close(); child.wait(); raise OSError('Cannot resume owned job')

    def close(self):
        if getattr(self,'handle',None):
            self.api.TerminateJobObject(self.handle,137)
            self.api.CloseHandle(self.handle); self.handle=None


def worker(folder,request):
    unix=os.name!='nt'
    if unix:
        os.setsid() # This live worker reserves its own process-group ID.
    argv=['/bin/sh','-c',request['command']] if unix else ['powershell.exe','-NoProfile','-NonInteractive','-Command','[Console]::OutputEncoding=[Text.UTF8Encoding]::new();'+request['command']]
    child=subprocess.Popen(argv,cwd=folder.parent.parent.parent,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
        creationflags=0 if unix else subprocess.CREATE_NO_WINDOW|0x4)
    tree=None if unix else WindowsTree(child)
    threads=[]
    for pipe,name in ((child.stdout,'stdout'),(child.stderr,'stderr')):
        thread=threading.Thread(target=drain,args=(pipe,folder/(name+'.bin')),daemon=True); thread.start(); threads.append(thread)
    save(folder/'status.json',{'id':request['id'],'state':'running','started_at':time.time()})
    deadline=time.monotonic()+request['seconds']; state='completed'; code=None
    try:
        while True:
            if (folder/'cancel').exists():
                state='cancelled'; break
            if time.monotonic()>=deadline:
                state='timed_out'; break
            code=child.poll()
            if code is not None:
                break
            time.sleep(.1)
        if not unix:
            tree.close(); child.wait(5)
        for thread in threads:
            thread.join(.5)
        pending={'id':request['id'],'state':state,'exit_code':code,'finished_at':time.time(),
            'termination_scope':'unix-process-group' if unix else 'windows-job-object',
            'truncated':any((folder/(name+'.truncated')).exists() for name in ('stdout','stderr'))}
        save(folder/'pending.json',pending)
    finally:
        if unix:
            # Includes worker and every descendant in its session. The monitor
            # outside this group confirms termination before publishing final state.
            os.killpg(os.getpgrp(),signal.SIGKILL)
        elif tree:
            tree.close()


def main():
    folder=Path(sys.argv[1]); request=json.loads((folder/'request.json').read_text(encoding='utf-8'))
    if len(sys.argv)>2:
        worker(folder,request); return
    # A timeout/disconnect never launches the same job twice.
    try:
        with (folder/'claimed').open('x') as stream:
            stream.write(request['id'])
    except FileExistsError:
        return
    save(folder/'status.json',{'id':request['id'],'state':'starting'})
    try:
        child=subprocess.Popen([sys.executable,'-I','-B',__file__,str(folder),'worker'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        child.wait(request['seconds']+20)
        pending=folder/'pending.json'
        result=json.loads(pending.read_text(encoding='utf-8')) if pending.exists() else {'id':request['id'],'state':'failed','error':'Runner exited without a completion receipt'}
        result['tree_terminated']=True
        save(folder/'status.json',result)
    except Exception as error:
        save(folder/'status.json',{'id':request['id'],'state':'failed','error':str(error)[:256]})


if __name__=='__main__':
    main()
