"""Bounded, atomic metadata for the local control plane."""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import threading
from uuid import uuid4

from .errors import AgenticVMError


def fail(message, code='control_error'):
    raise AgenticVMError(message, code)


def identifier(value):
    if not isinstance(value,str) or re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,31}',value) is None:
        fail('Use a session ID of 1-32 lower-case letters, numbers, dashes or underscores.','invalid_session')
    return value


def checked(path, root):
    path, root = Path(path).absolute(), Path(root).absolute()
    if '..' in path.parts or not path.is_relative_to(root):
        fail('Control data must stay in its owned folder.','invalid_path')
    for parent in (path,*path.parents):
        if parent.is_symlink() or getattr(parent,'is_junction',lambda:False)():
            fail('Control paths must not redirect.','invalid_path')
    return path


def digest(path):
    with Path(path).open('rb') as source:
        return hashlib.file_digest(source,'sha256').hexdigest()


def load_json(path, *, limit=1024*1024, default=None):
    path=Path(path)
    if not path.exists():
        return default
    if path.stat().st_size>limit:
        fail('Control metadata exceeds its size limit.','invalid_state')
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except (ValueError,UnicodeError) as error:
        fail('Control metadata is invalid.','invalid_state')


def save_json(path, data):
    path=Path(path)
    path.parent.mkdir(parents=True,exist_ok=True)
    temporary=path.with_name(path.name+'.'+uuid4().hex+'.tmp')
    with temporary.open('x',encoding='utf-8') as output:
        json.dump(data,output,ensure_ascii=True,sort_keys=True)
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary,path)


class Metadata:
    def __init__(self, root):
        self.root=checked(Path(root).absolute(),Path(root).absolute())
        self.thread_lock=threading.RLock()
        self.depth=0

    def path(self, relative):
        return checked(self.root/relative,self.root)

    @contextmanager
    def lock(self):
        with self.thread_lock:
            if self.depth:
                self.depth+=1
                try:
                    yield
                finally:
                    self.depth-=1
                return
            self.path('.lock').parent.mkdir(parents=True,exist_ok=True)
            with self.path('.lock').open('a+b') as stream:
                if stream.seek(0,os.SEEK_END)==0:
                    stream.write(b'\0')
                    stream.flush()
                stream.seek(0)
                try:
                    if os.name=='nt':
                        import msvcrt
                        msvcrt.locking(stream.fileno(),msvcrt.LK_NBLCK,1)
                    else:
                        import fcntl
                        fcntl.flock(stream,fcntl.LOCK_EX|fcntl.LOCK_NB)
                except OSError:
                    fail('Control metadata is busy. Retry after observing state.','session_busy')
                try:
                    self.depth=1
                    yield
                finally:
                    self.depth=0
                    stream.seek(0)
                    if os.name=='nt':
                        msvcrt.locking(stream.fileno(),msvcrt.LK_UNLCK,1)
                    else:
                        fcntl.flock(stream,fcntl.LOCK_UN)
