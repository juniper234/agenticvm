"""Run every host regression with explicit dependencies, temp paths and receipts."""
from __future__ import annotations
import argparse
import hashlib
import importlib
import json
import os
from pathlib import Path
import random
import subprocess
import sys
import tempfile
import time
import unittest
from uuid import uuid4

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))


def source_pins():
    try:
        result=subprocess.run(['git','ls-files','-z'],cwd=ROOT,capture_output=True,check=True)
        names=[name for name in result.stdout.decode().split('\0') if name]
    except (FileNotFoundError,subprocess.CalledProcessError):
        ignored={'__pycache__','bin','obj','node_modules','.git'}
        names=[file.relative_to(ROOT).as_posix() for directory in ('src','tests','scripts','guest','desktop')
               for file in (ROOT/directory).rglob('*') if file.is_file() and not ignored.intersection(file.parts)]
        names += [file.relative_to(ROOT).as_posix() for file in (ROOT/'tools').glob('*-lock.json')]
        names += [name for name in ('pyproject.toml','requirements-test.txt') if (ROOT/name).is_file()]
    return {name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in names}


def flatten(suite):
    for item in suite:
        if isinstance(item,unittest.TestSuite):yield from flatten(item)
        else:yield item


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--temp-root',type=Path)
    parser.add_argument('--order',choices=['normal','reverse','shuffle'],default='normal')
    parser.add_argument('--seed',type=int,default=26026)
    args=parser.parse_args()
    for module in ('nacl','libtorrent','pefile','pyghmi','pycdlib','virt.peutils.pesign'):
        try:importlib.import_module(module)
        except ImportError as error:raise RuntimeError('Missing host-test dependency '+module+'; prepare the pinned test environment or install requirements-test.txt') from error
    temp=(args.temp_root or Path(tempfile.gettempdir())).resolve()
    if not temp.is_dir() or len(str(temp/'tmpabcdefgh'/'AgenticVM'/str(uuid4())/'q').encode('utf-8'))>=108:
        raise ValueError('Choose an existing writable shorter --temp-root for the real private-socket tests (107-byte OS limit)')
    with tempfile.NamedTemporaryFile(dir=temp):pass
    prior_temp=tempfile.tempdir
    prior={key:os.environ.get(key) for key in ('TEMP','TMP','AGENTICVM_SOCKET_ROOT')}
    started=time.monotonic()
    folder=ROOT/'runtime/test-results'/uuid4().hex
    folder.mkdir(parents=True)
    before=source_pins()
    try:
        tempfile.tempdir=str(temp)
        os.environ.update(TEMP=str(temp),TMP=str(temp))
        os.environ.pop('AGENTICVM_SOCKET_ROOT',None)
        tests=list(flatten(unittest.defaultTestLoader.discover(str(ROOT/'tests'))))
        if args.order=='reverse':tests.reverse()
        elif args.order=='shuffle':random.Random(args.seed).shuffle(tests)
        with (folder/'tests.log').open('w',encoding='utf-8') as log:
            result=unittest.TextTestRunner(stream=log,verbosity=2).run(unittest.TestSuite(tests))
        after=source_pins()
        receipt={'tests':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),
                 'skipped':len(result.skipped),'skip_reasons':[reason for _,reason in result.skipped],
                 'source_changed':before!=after,'source_sha256':after,'order':args.order,'seed':args.seed,
                 'python':sys.version.split()[0],'seconds':round(time.monotonic()-started,2),
                 'native_vm_launched':False,'passed':result.wasSuccessful() and before==after}
        (folder/'report.json').write_text(json.dumps(receipt,indent=2)+'\n',encoding='utf-8')
        print(json.dumps({key:value for key,value in receipt.items() if key not in {'source_sha256','skip_reasons'}}|{'receipt':str(folder/'report.json')}))
        return 0 if receipt['passed'] else 1
    finally:
        tempfile.tempdir=prior_temp
        for key,value in prior.items():
            if value is None:os.environ.pop(key,None)
            else:os.environ[key]=value


if __name__=='__main__':raise SystemExit(main())
