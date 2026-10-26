"""Reviewed user-scoped SSH bootstrap for one explicitly authorized lab VM.

CONFIG is supplied by the mother over authenticated SSH. No discovery, remote
command facility or recursive propagation is exposed by this installer.
"""
from __future__ import annotations
import hashlib,http.client,json,os,shutil,ssl,subprocess,tarfile,time,urllib.request
from pathlib import Path,PurePosixPath

BASE=Path('/workspace')
LIMITS={'model.gguf':250*1024**2,'llama.tar.gz':24*1024**2,
        'libgomp.so.1':1024**2,'agent.tar.gz':256*1024}

def save(path,value):
    temp=path.with_suffix('.tmp')
    with temp.open('w') as stream:
        json.dump(value,stream,sort_keys=True);stream.flush();os.fsync(stream.fileno())
    temp.replace(path)

def digest(path):
    with path.open('rb') as stream: return hashlib.file_digest(stream,'sha256').hexdigest()

def download(opener,url,destination,entry,*,attempts=3):
    """Bounded resume; a complete independent digest precedes activation."""
    if entry['name'] not in LIMITS or type(entry['bytes']) is not int or not 0<entry['bytes']<=LIMITS[entry['name']]:
        raise ValueError('Unapproved package or excessive asset size')
    expected=entry['sha256']
    if len(expected)!=64 or any(c not in '0123456789abcdef' for c in expected): raise ValueError('Invalid asset pin')
    if destination.exists():
        if destination.stat().st_size==entry['bytes'] and digest(destination)==expected:
            return {'name':entry['name'],'bytes':entry['bytes'],'cached_verified':True,'resumed':False}
        raise ValueError('Existing installed asset does not match its pin')
    partial=destination.with_suffix(destination.suffix+'.partial')
    resumed=False
    for attempt in range(attempts):
        offset=partial.stat().st_size if partial.exists() else 0
        if offset>entry['bytes']: raise ValueError('Oversized partial download')
        if offset==entry['bytes']: break
        request=urllib.request.Request(url,headers={'Range':f'bytes={offset}-'} if offset else {})
        try:
            with opener.open(request,timeout=15) as response:
                append=bool(offset and response.status==206)
                if append and response.headers.get('Content-Range')!=f'bytes {offset}-{entry["bytes"]-1}/{entry["bytes"]}':
                    raise ValueError('Wrong resume offset')
                if response.status not in (200,206) or (response.status==206 and not append):
                    raise ValueError('Unexpected download status')
                resumed|=append
                count=offset if append else 0
                with partial.open('ab' if append else 'wb') as output:
                    while chunk:=response.read(256*1024):
                        count+=len(chunk)
                        if count>entry['bytes']: raise ValueError('Asset exceeds approved byte count')
                        output.write(chunk)
                    output.flush();os.fsync(output.fileno())
                if count!=entry['bytes']: raise OSError('Interrupted asset transfer')
            break
        except (OSError,http.client.IncompleteRead):
            if attempt+1==attempts: raise
            time.sleep(.2)
    if partial.stat().st_size!=entry['bytes'] or digest(partial)!=expected:
        raise ValueError('Asset integrity verification failed')
    partial.replace(destination)
    return {'name':entry['name'],'bytes':entry['bytes'],'cached_verified':False,'resumed':resumed}

def unpack(archive,destination,kind):
    """Do not use extractall; approve every path/type and bounded payload."""
    destination.mkdir(parents=True,exist_ok=True)
    with tarfile.open(archive) as source:
        for member in source:
            path=PurePosixPath(member.name)
            if path.is_absolute() or '..' in path.parts or member.size>32*1024**2:
                raise ValueError('Unsafe archive member')
            if kind=='agent':
                if len(path.parts)!=1 or path.name not in ('lan_agent.py','local_lfm.py') or not member.isfile():
                    raise ValueError('Unexpected agent member')
            elif not (path.parts and path.parts[0]=='llama-b11711' and len(path.parts)<=2):
                raise ValueError('Unexpected inference release member')
            target=destination/str(path)
            if member.isdir(): target.mkdir(exist_ok=True)
            elif member.isfile():
                target.parent.mkdir(parents=True,exist_ok=True)
                with source.extractfile(member) as src,target.open('wb') as output: shutil.copyfileobj(src,output,256*1024)
                target.chmod(0o500 if kind=='agent' else member.mode&0o755)
            elif member.issym() and kind=='llama' and '/' not in member.linkname and member.linkname not in ('.','..'):
                if not target.exists() and not target.is_symlink(): target.symlink_to(member.linkname)
            else: raise ValueError('Unsupported archive entry')

def process_identity(pid):
    try:
        return {'pid':pid,'start_ticks':Path(f'/proc/{pid}/stat').read_text().rsplit(')',1)[1].split()[19],
                'argv':Path(f'/proc/{pid}/cmdline').read_bytes().decode().rstrip('\0').split('\0')}
    except FileNotFoundError: return None

def install(config, *, fetch=download):
    if config['identity']!='sprout-4' or config['mother']!='https://192.0.2.1:8443':
        raise ValueError('This lab bootstrap accepts only the preauthorized fourth sprout')
    state_path=BASE/'enrollment-state.json'
    if state_path.exists():
        state=json.loads(state_path.read_text())
        if state['request_id']!=config['request_id'] or state['manifest_sha256']!=config['manifest_sha256']:
            raise ValueError('An enrollment already owns this workspace')
        if state['phase']=='started':
            if process_identity(state['process']['pid'])!=state['process']: raise ValueError('Prior installation process cannot be safely adopted')
            return {'ok':True,'duplicate':True,'process':state['process']}
        if state['phase'] not in ('downloading','verified'):
            raise ValueError('Interrupted activation requires reconciliation, not task replay')
    else:
        state={'request_id':config['request_id'],'manifest_sha256':config['manifest_sha256'],'phase':'downloading'}
        save(state_path,state)
    context=ssl.create_default_context(cadata=config['mother_certificate'])
    context.minimum_version=ssl.TLSVersion.TLSv1_3
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=context))
    admission=urllib.request.Request(config['mother']+'/admission',data=json.dumps({
        'request_id':config['request_id'],'identity':config['identity'],'grant':config['grant']}).encode(),
        headers={'Content-Type':'application/json'})
    with opener.open(admission,timeout=10) as response:
        admitted=json.loads(response.read(4097))
    if admitted!={'ok':True,'admitted':True}: raise ValueError('Enrollment admission rejected')
    with opener.open(config['mother']+'/manifest',timeout=10) as response: raw=response.read(65537)
    if len(raw)>65536 or hashlib.sha256(raw).hexdigest()!=config['manifest_sha256']: raise ValueError('Manifest pin mismatch')
    manifest=json.loads(raw)
    if set(manifest['files'])!=set(LIMITS): raise ValueError('Unexpected package inventory')
    stage=BASE/'download';stage.mkdir(exist_ok=True)
    receipts=[]
    for name in LIMITS:
        item={**manifest['files'][name],'name':name}
        receipts.append(fetch(opener,config['mother']+'/assets/'+name,stage/name,item))
    state.update(phase='verified',downloads=receipts);save(state_path,state)
    peer=BASE/'peer';peer.mkdir(exist_ok=True)
    unpack(stage/'agent.tar.gz',peer,'agent');unpack(stage/'llama.tar.gz',BASE/'llama','llama')
    dependencies=BASE/'dependencies';dependencies.mkdir(exist_ok=True)
    for source,target in ((stage/'model.gguf',BASE/'model.gguf'),(stage/'libgomp.so.1',dependencies/'libgomp.so.1')):
        if not target.exists(): os.link(source,target)
        if digest(target)!=manifest['files'][source.name]['sha256']: raise ValueError('Activation asset mismatch')
    state['phase']='activating';save(state_path,state)
    subprocess.run(['/usr/bin/openssl','req','-x509','-newkey','ed25519','-nodes','-days','1',
        '-keyout',str(BASE/'identity.key'),'-out',str(BASE/'identity.pem'),'-subj','/CN=sprout-4',
        '-addext','subjectAltName=URI:urn:agenticvm:lan:sprout-4,IP:192.0.2.4',
        '-addext','basicConstraints=critical,CA:TRUE',
        '-addext','keyUsage=critical,digitalSignature,keyCertSign,cRLSign'],check=True,capture_output=True,timeout=15)
    config_path=BASE/'lan-config.json';save(config_path,config)
    with (BASE/'agent.log').open('ab') as log:
        child=subprocess.Popen(['/usr/bin/python3','-I',str(peer/'lan_agent.py')],stdin=subprocess.DEVNULL,
                               stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
    identity=process_identity(child.pid)
    if not identity: raise RuntimeError('Installed agent exited before process binding')
    state.update(phase='started',process=identity);save(state_path,state)
    os.sync()
    return {'ok':True,'duplicate':False,'process':identity,'downloads':receipts,
            'identity_generated_inside_target':True,'model_sha256':digest(BASE/'model.gguf')}

if __name__=='__main__':
    try: print(json.dumps(install(CONFIG),sort_keys=True),flush=True)
    except Exception as error:
        print(json.dumps({'ok':False,'error':type(error).__name__+': '+str(error)}),flush=True)
        raise SystemExit(1)
