"""Assemble a standard systemd UKI from a pinned stub and bounded local inputs."""
import hashlib,struct,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools/python/firmware-v1'))
import pefile
from virt.peutils.pesign import pe_authenticode_hash as _upstream_authenticode_hash

def pe_authenticode_hash(image):
    # PE .bss sections have no file bytes. Exclude them from the upstream
    # iterator; v24.11 otherwise logs false section-offset errors for iPXE.
    sections=image.sections
    try:
        image.sections=[section for section in sections if section.SizeOfRawData]
        return _upstream_authenticode_hash(image)
    finally: image.sections=sections

def build(stub,kernel,ram,output):
    if len(kernel)>32*1024**2 or len(ram)>96*1024**2: raise ValueError('UKI payload bound exceeded')
    data=bytearray(stub.read_bytes());pe=pefile.PE(data=bytes(data))
    if pe.OPTIONAL_HEADER.Subsystem!=10 or pe.FILE_HEADER.Machine!=0x8664: raise ValueError('Expected x64 UEFI application stub')
    parts={'.osrel':b'ID=garden\nNAME="Garden owned network boot lab"\n',
        '.cmdline':b'console=ttyS0,115200n8 rdinit=/init panic=1\0','.linux':kernel,'.initrd':ram}
    existing={s.Name.rstrip(b'\0').decode() for s in pe.sections}
    if existing.intersection(parts): raise ValueError('Stub already contains embedded OS payload')
    align=lambda value,unit:(value+unit-1)//unit*unit
    table=pe.sections[0].get_file_offset();count=pe.FILE_HEADER.NumberOfSections
    if table+(count+len(parts))*40>pe.OPTIONAL_HEADER.SizeOfHeaders: raise ValueError('Insufficient reserved PE section header space')
    rva=align(max(s.VirtualAddress+s.Misc_VirtualSize for s in pe.sections),pe.OPTIONAL_HEADER.SectionAlignment)
    additions={};initialized=pe.OPTIONAL_HEADER.SizeOfInitializedData
    for name,payload in parts.items():
        raw=align(len(data),pe.OPTIONAL_HEADER.FileAlignment);size=align(len(payload),pe.OPTIONAL_HEADER.FileAlignment)
        data.extend(bytes(raw-len(data)));data.extend(payload);data.extend(bytes(size-len(payload)))
        header=struct.pack('<8sIIIIIIHHI',name.encode().ljust(8,b'\0'),len(payload),rva,size,raw,0,0,0,0,0x40000040)
        data[table+count*40:table+(count+1)*40]=header;count+=1;initialized+=size
        additions[name]={'bytes':len(payload),'sha256':hashlib.sha256(payload).hexdigest()}
        rva=align(rva+len(payload),pe.OPTIONAL_HEADER.SectionAlignment)
    struct.pack_into('<H',data,pe.FILE_HEADER.get_file_offset()+2,count)
    optional=pe.OPTIONAL_HEADER.get_file_offset()
    struct.pack_into('<I',data,optional+8,initialized);struct.pack_into('<I',data,optional+56,rva)
    struct.pack_into('<I',data,optional+64,0)
    security=pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].get_file_offset();struct.pack_into('<II',data,security,0,0)
    final=pefile.PE(data=bytes(data));struct.pack_into('<I',data,optional+64,final.generate_checksum())
    final=pefile.PE(data=bytes(data))
    for name,payload in parts.items():
        section=next(s for s in final.sections if s.Name.rstrip(b'\0').decode()==name)
        if section.get_data()[:section.Misc_VirtualSize]!=payload: raise ValueError('Embedded UKI section changed')
    with output.open('xb') as stream: stream.write(data)
    return {'sha256':hashlib.sha256(data).hexdigest(),'authenticode_sha256':pe_authenticode_hash(final).hex(),
        'bytes':len(data),'embedded_sections':additions,'trust_method':'firmware db hash allowlist of the complete UKI'}
