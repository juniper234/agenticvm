"""Build a separate Debian network-boot lab from authenticated Debian packages."""
from __future__ import annotations
import gzip,hashlib,importlib.util,json,stat,sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from agenticvm.ext2 import Node,build_ext2

def load(name,file):
    spec=importlib.util.spec_from_file_location(name,ROOT/'scripts'/file)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

desktop=load('pxe_desktop','build-linux-desktop.py')
probe=desktop.probe

def record(path):
    with path.open('rb') as source: sha=hashlib.file_digest(source,'sha256').hexdigest()
    return {'path':str(path.relative_to(ROOT)),'bytes':path.stat().st_size,'sha256':sha}

def build():
    output=ROOT/'runtime/linux-pxe-base-v3';output.mkdir(exist_ok=True)
    manifest_path=output/'build-manifest.json'
    if manifest_path.exists():
        print('Existing PXE build retained: '+str(manifest_path));return
    requested=['base-files','base-passwd','busybox-static','openssl','python3','ca-certificates',
               'e2fsprogs','procps','kmod','iproute2','libstdc++6','dnsmasq-base','ipxe-qemu']
    packages,lock=desktop.packages_lib.prepare_packages(ROOT/'downloads/debian/trixie',requested,output/'package-lock.json')
    content=output/'content';content.mkdir(exist_ok=True)
    nodes=desktop.read_packages(packages,content)
    def add(name,data,mode=0o644): nodes[name]=Node(stat.S_IFREG|mode,data)
    for name in ('dev','proc','sys','tmp','run','workspace','root','mnt','usr/local/bin'):
        nodes.setdefault(name,Node(stat.S_IFDIR|0o755))
    add('etc/passwd',b'root:x:0:0:root:/root:/bin/sh\ngarden:x:1000:1000:Garden lab:/workspace:/bin/sh\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n')
    add('etc/group',b'root:x:0:\ntty:x:5:\ngarden:x:1000:\nnogroup:x:65534:\n')
    add('etc/shadow',b'root:!:0:0:99999:7:::\ngarden:!:0:0:99999:7:::\n',0o600)
    add('etc/fstab',b'# No host mounts or SSH service.\n')
    add('etc/hostname',b'garden-pxe-lab\n')
    add('etc/ld.so.conf',b'/usr/local/lib\n/usr/lib/x86_64-linux-gnu\n/lib/x86_64-linux-gnu\n')
    old=json.loads((ROOT/'runtime/linux-desktop/build-manifest.json').read_text())
    module_base=ROOT/'runtime/linux-desktop/kernel-modules/modules'/old['kernel_version']
    paths=old.get('all_modules',old['desktop_modules'])
    for name in paths: add('usr/lib/modules/'+old['kernel_version']+'/'+name,module_base/name)
    for name in ('modules.dep','modules.alias','modules.builtin','modules.order','modules.softdep'):
        if (module_base/name).exists(): add('usr/lib/modules/'+old['kernel_version']+'/'+name,module_base/name)
    # Unlike the ext2 writer, the kernel's cpio unpacker does not synthesize
    # absent parent directories for the manually added kernel modules.
    for name in list(nodes):
        for parent in Path(name).parents:
            if parent.as_posix()!='.': nodes.setdefault(parent.as_posix(),Node(stat.S_IFDIR|0o755))
    if any('ssh' in item['name'] for item in packages): raise ValueError('SSH must not be part of this image')
    root=output/'rootfs.ext2';build_ext2(root,nodes,label='GARDEN_PXE_BASE')
    # The NIC ROM comes from a GPG-authenticated Debian package, not an arbitrary binary download.
    candidates=[(name,node) for name,node in nodes.items() if name.endswith('/pxe-e1000.rom')]
    if len(candidates)!=1: raise ValueError('Expected exactly one packaged e1000 iPXE ROM')
    rom=output/'pxe-e1000.rom';rom.write_bytes(candidates[0][1].data.read_bytes())
    # A plain Debian RAM root, with no garden agent, model, SSH or enrollment credentials.
    entries={}
    for name,node in nodes.items():
        if not name or name.startswith(('usr/share/doc/','usr/share/man/','usr/share/locale/','usr/lib/ipxe/')):
            continue
        # build_ext2 populates shared directory Node.data with its block
        # records. cpio directory entries must instead have an empty body.
        data=b'' if stat.S_ISDIR(node.mode) else (node.data.read_bytes() if isinstance(node.data,Path) else node.data)
        entries[name]=(node.mode,data,0,0)
    entries['dev/console']=(stat.S_IFCHR|0o600,b'',5,1)
    entries['init']=(stat.S_IFREG|0o755,(ROOT/'guest/pxe-init.sh').read_bytes().replace(b'\r\n',b'\n'),0,0)
    # Store the plain entries once; each run adds only a public CA and a bounded provisioner.
    ram=output/'plain-root.cpio.gz';ram.write_bytes(gzip.compress(probe.make_newc(entries),compresslevel=6,mtime=0))
    image_source,provenance=probe.verified_iso()
    iso=probe.pycdlib.PyCdlib();iso.open(str(image_source))
    try:
        kernel=output/'vmlinuz';kernel.write_bytes(probe.extract(iso,'/boot/vmlinuz-virt'))
        original=probe.source_initrd(iso)
        files={name:(stat.S_IFDIR|0o755,b'',0,0) for name in ('bin','lib','dev','proc','sys','lower','overlay','newroot','modules','assets')}
        module_names=[]
        for module in old['boot_modules']:
            name='modules/'+Path(module).name
            files[name]=(stat.S_IFREG|0o644,(module_base/module).read_bytes(),0,0);module_names.append(name)
        init=(ROOT/'guest/peer-bootstrap.sh').read_bytes().replace(b'\r\n',b'\n')
        init=init.replace(b'@BOOT_MODULES@',' '.join(module_names).encode())
        init=init.replace(b'$BB cp /assets/agentd /newroot/usr/local/bin/agentd || exit 1\n',b'')
        init=init.replace(b' /newroot/usr/local/bin/agentd',b'')
        files.update({'init':(stat.S_IFREG|0o755,init,0,0),
            'assets/peer-init.sh':(stat.S_IFREG|0o755,(ROOT/'guest/pxe-lan-init.sh').read_bytes().replace(b'\r\n',b'\n'),0,0),
            'bin/busybox':(*original['usr/bin/busybox'],0,0),
            'bin/sh':(stat.S_IFLNK|0o777,b'busybox',0,0),
            'lib/ld-musl-x86_64.so.1':(*original['usr/lib/ld-musl-x86_64.so.1'],0,0),
            'lib/libc.musl-x86_64.so.1':(stat.S_IFLNK|0o777,b'ld-musl-x86_64.so.1',0,0),
            'dev/console':(stat.S_IFCHR|0o600,b'',5,1)})
        boot=desktop.make_boot_iso(iso,gzip.compress(probe.make_newc(files),mtime=0),output,'peer')
    finally: iso.close()
    manifest={'schema':'agenticvm.pxe-base.v1','os':'Debian 13','kernel':provenance,
        'root':record(root),'iso':record(boot),'rom':record(rom),'vmlinuz':record(kernel),
        'ram_root':record(ram),'package_lock':record(output/'package-lock.json'),
        'profiles':{name:record(ROOT/'guest'/name) for name in ('pxe-init.sh','pxe-lan-init.sh')},
        'ssh_included':False,'garden_agent_or_model_in_ram_root':False,
        'firmware_trust':'GPG-authenticated Debian iPXE ROM; initial PXE network must be trusted; no secure boot claim'}
    manifest_path.write_text(json.dumps(manifest,indent=2)+'\n');print(json.dumps(manifest,indent=2))

if __name__=='__main__': build()
