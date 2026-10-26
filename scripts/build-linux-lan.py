"""Build a separate plain Debian LAN lab base; no AgenticVM control daemon."""
from __future__ import annotations
import gzip,hashlib,importlib.util,json,stat,sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from agenticvm.ext2 import Node,build_ext2,read_image_file
spec=importlib.util.spec_from_file_location('desktop',ROOT/'scripts/build-linux-desktop.py')
desktop=importlib.util.module_from_spec(spec);spec.loader.exec_module(desktop)
probe=desktop.probe

def build():
    output=ROOT/'runtime/linux-lan-base-v3'
    output.mkdir(exist_ok=True)
    if (output/'build-manifest.json').exists():
        return print('Existing LAN base retained; manifest: '+str(output/'build-manifest.json'))
    requested=['base-files','base-passwd','busybox-static','openssl','openssh-server',
               'openssh-client','python3','ca-certificates','e2fsprogs','procps','kmod','iproute2','libstdc++6']
    packages,lock=desktop.packages_lib.prepare_packages(ROOT/'downloads/debian/trixie',requested,
                                                       output/'package-lock.json')
    content=output/'content';content.mkdir(exist_ok=True)
    nodes=desktop.read_packages(packages,content)
    def add(name,data,mode=0o644): nodes[name]=Node(stat.S_IFREG|mode,data)
    for name in ('dev','proc','sys','tmp','run','workspace','root','mnt','usr/local/bin'):
        nodes.setdefault(name,Node(stat.S_IFDIR|0o755))
    add('etc/passwd',b'root:x:0:0:root:/root:/bin/sh\nsshd:x:101:65534:sshd:/run/sshd:/usr/sbin/nologin\ngarden:x:1000:1000:Garden lab:/workspace:/bin/sh\n')
    add('etc/group',b'root:x:0:\ntty:x:5:\ngarden:x:1000:\nnogroup:x:65534:\n')
    # Public-key-only SSH is deliberately provisioned for the positive target.
    # An unlocked password field is required by OpenSSH's account check;
    # all password/interactive authentication is disabled in sshd_config.
    add('etc/shadow',b'root:!:0:0:99999:7:::\ngarden:*:0:0:99999:7:::\n',0o600)
    add('etc/fstab',b'# Read-only base plus private lab workspace.\n')
    add('etc/hostname',b'garden-lan-lab\n')
    add('etc/ld.so.conf',b'/usr/local/lib\n/usr/lib/x86_64-linux-gnu\n/lib/x86_64-linux-gnu\n')
    base=json.loads((ROOT/'runtime/linux-desktop/build-manifest.json').read_text())
    module_base=ROOT/'runtime/linux-desktop/kernel-modules/modules'/base['kernel_version']
    for module in base['all_modules'] if 'all_modules' in base else base['desktop_modules']:
        add('usr/lib/modules/'+base['kernel_version']+'/'+module,module_base/module)
    for name in ('modules.dep','modules.alias','modules.builtin','modules.order','modules.softdep'):
        if (module_base/name).exists(): add('usr/lib/modules/'+base['kernel_version']+'/'+name,module_base/name)
    root=output/'rootfs.ext2'
    build_ext2(root,nodes,label='GARDEN_LAN_BASE')
    for forbidden in ('usr/local/bin/agentd','workspace/model.gguf','workspace/peer/garden_agent.py'):
        try: read_image_file(root,forbidden)
        except FileNotFoundError: pass
        else: raise ValueError('Agent software unexpectedly included: '+forbidden)
    kernel,provenance=probe.verified_iso()
    iso=probe.pycdlib.PyCdlib();iso.open(str(kernel))
    try:
        original=probe.source_initrd(iso)
        files={name:(stat.S_IFDIR|0o755,b'',0,0) for name in
               ('bin','lib','dev','proc','sys','lower','overlay','newroot','modules','assets')}
        paths=[]
        for module in base['boot_modules']:
            name='modules/'+Path(module).name
            files[name]=(stat.S_IFREG|0o644,(module_base/module).read_bytes(),0,0);paths.append(name)
        init=(ROOT/'guest/peer-bootstrap.sh').read_bytes().replace(b'\r\n',b'\n')
        init=init.replace(b'@BOOT_MODULES@',' '.join(paths).encode())
        init=init.replace(b'$BB cp /assets/agentd /newroot/usr/local/bin/agentd || exit 1\n',b'')
        init=init.replace(b' /newroot/usr/local/bin/agentd',b'')
        init=init.replace(b'AgenticVM: mounting immutable Debian agent root.',b'Plain Debian LAN lab: mounting agent-free root.')
        files.update({'init':(stat.S_IFREG|0o755,init,0,0),
            'assets/peer-init.sh':(stat.S_IFREG|0o755,(ROOT/'guest/lan-init.sh').read_bytes().replace(b'\r\n',b'\n'),0,0),
            'bin/busybox':(*original['usr/bin/busybox'],0,0),
            'bin/sh':(stat.S_IFLNK|0o777,b'busybox',0,0),
            'lib/ld-musl-x86_64.so.1':(*original['usr/lib/ld-musl-x86_64.so.1'],0,0),
            'lib/libc.musl-x86_64.so.1':(stat.S_IFLNK|0o777,b'ld-musl-x86_64.so.1',0,0),
            'dev/console':(stat.S_IFCHR|0o600,b'',5,1)})
        image=desktop.make_boot_iso(iso,gzip.compress(probe.make_newc(files),mtime=0),output,'peer')
    finally: iso.close()
    def record(path):
        with path.open('rb') as stream: digest=hashlib.file_digest(stream,'sha256').hexdigest()
        return {'path':str(path.relative_to(ROOT)),'bytes':path.stat().st_size,'sha256':digest}
    manifest={'schema':'agenticvm.lan-base.v1','root':record(root),'iso':record(image),
        'os':'Debian 13','garden_agent_preinstalled':False,'agenticvm_control_daemon':False,
        'kernel':provenance,'package_lock':record(output/'package-lock.json'),
        'runtime_verified':False,'boot_profile':record(ROOT/'guest/lan-init.sh')}
    (output/'build-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps(manifest,indent=2))

if __name__=='__main__': build()
