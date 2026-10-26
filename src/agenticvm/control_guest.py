"""Small guest-only command/file adapter used by jobs and sync."""
import base64
import hashlib
import json
from pathlib import PurePosixPath
import shlex
from uuid import uuid4

from .control_store import fail
from .control_diagnostics import unwrap

MAX_FILE=1048576


class Guest:
    def __init__(self,controller):
        self.controller=controller
        self.vm=controller.profile

    @property
    def root(self):
        return 'C:/workspace' if self.vm=='windows' else '/data/local/tmp/agenticvm' if self.vm=='android' else '/workspace'

    def path(self,value):
        if not isinstance(value,str) or not value or len(value)>1024 or any(ord(c)<32 for c in value) or '\\' in value:
            fail('Choose a file inside the guest workspace.','invalid_path')
        if self.vm=='android' and value.startswith('/workspace/'):
            value=self.root+value[len('/workspace'):]
        prefix=self.root+'/'
        if not value.startswith(prefix) or any(p in {'..','.'} for p in value.split('/')) or ':' in value[len(prefix):] or not PurePosixPath(value).name:
            fail('Choose a file inside the guest workspace.','invalid_path')
        return value

    def execute(self,command):
        return unwrap(self.controller.action({'action':'exec','command':command}))

    def boot_id(self):
        command="(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')" if self.vm=='windows' else 'cat /proc/sys/kernel/random/boot_id'
        value=self.run(command).get('stdout','').strip()
        if not value or len(value)>128:
            fail('Could not establish guest boot identity.','protocol_error')
        return value

    def run(self,command):
        result=self.execute(command)
        if result.get('exit_code')!=0:
            fail('Guest helper failed: '+str(result.get('stderr',''))[:512],'guest_helper_failed')
        return result

    def python(self,source):
        encoded=base64.b64encode(source.encode()).decode()
        code="import base64;exec(base64.b64decode('"+encoded+"'))"
        if self.vm=='windows':
            command="& 'C:/ProgramData/AgenticVM/python/python.exe' -I -B -c '"+code.replace("'","''")+"'"
        else:
            command='python3 -I -B -c '+shlex.quote(code)
        return self.run(command)

    def mkdir(self,path):
        path=self.path(path+'/placeholder').rsplit('/',1)[0]
        if self.vm=='android':
            self.run('mkdir -p '+shlex.quote(path))
        else:
            self.python('from pathlib import Path\nPath('+repr(path)+').mkdir(parents=True,exist_ok=True)')

    def write(self,path,data):
        path=self.path(path)
        if not isinstance(data,bytes) or len(data)>MAX_FILE:
            fail('Files are limited to 1 MiB.','file_too_large')
        self.mkdir(path.rsplit('/',1)[0])
        return unwrap(self.controller.action({'action':'upload','path':path,'data_b64':base64.b64encode(data).decode()}))

    def read(self,path):
        return self.controller.download(self.path(path))[0]

    def optional(self,path):
        path=self.path(path)
        # Missing files are explicit; an ownership or transfer failure is never
        # mistaken for an absent file and silently overwritten.
        if self.vm=='android':
            check=self.execute('if [ -f '+shlex.quote(path)+' ]; then exit 0; elif [ -e '+shlex.quote(path)+' ]; then exit 45; else exit 44; fi')
        else:
            check=self.python('from pathlib import Path\np=Path('+repr(path)+')\nprint("FILE" if p.is_file() else "OTHER" if p.exists() else "MISSING")')
            marker=check['stdout'].strip()
            if marker=='MISSING':
                return None
            if marker!='FILE':
                fail('Guest file is not regular.','invalid_path')
            return self.read(path)
        if check.get('exit_code')==44:
            return None
        if check.get('exit_code')!=0:
            fail('Guest file existence could not be established.','invalid_path')
        return self.read(path)

    def compare_write(self,path,data,expected):
        path=self.path(path)
        temporary=path+'.sync-'+uuid4().hex
        self.write(temporary,data)
        if self.vm=='android':
            wanted=expected or 'MISSING'
            q=shlex.quote
            command='p='+q(path)+'; t='+q(temporary)+'; h=MISSING; if [ -f "$p" ]; then h=$(sha256sum "$p"); h=${h%% *}; elif [ -e "$p" ] || [ -L "$p" ]; then exit 45; fi; if [ "$h" != '+q(wanted)+' ]; then rm -f "$t"; echo CONFLICT; else mv -f "$t" "$p" && echo APPLIED; fi'
            marker=self.run(command)['stdout'].strip()
        else:
            source='''from pathlib import Path
import hashlib,os
p=Path(PATH); t=Path(TEMP)
for node in (p,*p.parents):
 if node.is_symlink() or getattr(node,'is_junction',lambda:False)(): raise ValueError('redirected guest path')
h=hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None
if h!=EXPECTED:
 t.unlink(); print('CONFLICT')
else:
 os.replace(t,p); print('APPLIED')
'''.replace('PATH',repr(path)).replace('TEMP',repr(temporary)).replace('EXPECTED',repr(expected))
            marker=self.python(source)['stdout'].strip()
        if marker!='APPLIED':
            fail('Guest file changed during transfer. Both versions were preserved.','sync_conflict')
        return {'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}


def sha(data):
    return hashlib.sha256(data).hexdigest() if data is not None else None
