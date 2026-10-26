"""Provisioner downloaded as part of the trusted private-LAN boot image.

Only a public mother certificate and installer hash are embedded. Enrollment
configuration and installer are fetched over pinned TLS 1.3 after boot.
"""
from __future__ import annotations
import hashlib,json,os,ssl,time,urllib.request
from pathlib import Path

BASE=Path('/workspace')

def save(value):
    path=BASE/'pxe-result.json';tmp=path.with_suffix('.tmp')
    with tmp.open('w') as stream: json.dump(value,stream,sort_keys=True);stream.write('\n');stream.flush();os.fsync(stream.fileno())
    tmp.replace(path);os.sync()

def verified_installer(raw,expected):
    if len(raw)>64*1024 or hashlib.sha256(raw).hexdigest()!=expected:
        raise ValueError('PXE installer integrity verification failed before execution')
    return compile(raw,'<verified-network-installer>','exec')

def main():
    trust=json.loads(Path('/boot-trust.json').read_text())
    context=ssl.create_default_context(cadata=trust['mother_certificate'])
    context.minimum_version=context.maximum_version=ssl.TLSVersion.TLSv1_3
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=context))
    origin='https://192.0.2.1:8443'
    with opener.open(origin+'/pxe/config',timeout=15) as response: raw=response.read(32769)
    if len(raw)>32768: raise ValueError('Oversized provisioning configuration')
    config=json.loads(raw)
    if config['mother_certificate']!=trust['mother_certificate']: raise ValueError('Mother trust changed')
    with opener.open(origin+'/pxe/installer',timeout=15) as response: raw=response.read(65537)
    program=verified_installer(raw,trust['installer_sha256'])
    scope={'__name__':'verified_pxe_installer'};exec(program,scope)
    installed=scope['install'](config)
    repeated=scope['install'](config)
    if not installed['ok'] or installed['duplicate'] or not repeated['duplicate'] or repeated['process']!=installed['process']:
        raise ValueError('Idempotent installation process binding failed')
    receipt={'ok':True,'installed':installed,'duplicate':repeated,'installer_sha256':trust['installer_sha256'],
        'ssh_present':Path('/usr/sbin/sshd').exists() or Path('/usr/bin/ssh').exists(),
        'boot_source':'network','local_os_boot_disk':False}
    request=urllib.request.Request(origin+'/pxe/receipt',data=json.dumps({'request_id':config['request_id'],
        'identity':config['identity'],'grant':config['grant'],'receipt':receipt}).encode(),headers={'Content-Type':'application/json'})
    with opener.open(request,timeout=15) as response: accepted=json.loads(response.read(4097))
    if accepted!={'ok':True}: raise ValueError('Installation receipt was not accepted')
    save(receipt)

if __name__=='__main__':
    try: main()
    except Exception as error:
        save({'ok':False,'error':type(error).__name__+': '+str(error)})
        import traceback;traceback.print_exc()
