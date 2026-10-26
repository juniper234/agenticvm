"""Mother-only, finite PXE service on the isolated experiment's eth0.

No host network services, gateway, DNS, scanning, TFTP writes or arbitrary paths.
Initial boot is a trusted-LAN operation, not authenticated secure boot.
"""
from __future__ import annotations
import hashlib,http.server,json,os,subprocess,threading,time
from pathlib import Path

BASE=Path('/workspace')
FILES={'/boot.ipxe':'boot.ipxe','/vmlinuz':'vmlinuz','/initrd.gz':'initrd.gz'}

def save(path,value):
    tmp=path.with_suffix('.tmp');tmp.write_text(json.dumps(value,sort_keys=True)+'\n');tmp.chmod(0o644);tmp.replace(path)

def dnsmasq_config(case):
    # A test deliberately refuses the actual target's MAC. Unknown MACs never receive a lease.
    target='06' if case=='unapproved-mac' else '04'
    return '''port=0
interface=eth0
listen-address=192.0.2.1
bind-interfaces
no-resolv
no-hosts
dhcp-authoritative
dhcp-range=192.0.2.0,static,255.255.255.0,2m
dhcp-host=52:54:00:4c:41:'''+target+''',set:sprout,192.0.2.4
dhcp-ignore=tag:!sprout
dhcp-option=option:router
dhcp-option=option:dns-server
dhcp-boot=http://192.0.2.1:8080/boot.ipxe,,192.0.2.1
dhcp-leasefile=/run/pxe.leases
pid-file=/run/pxe-dhcp.pid
log-dhcp
log-facility=-
user=root
'''

class BootHTTP(http.server.BaseHTTPRequestHandler):
    def log_message(self,*args): pass
    def do_GET(self):
        service=self.server
        if self.client_address[0]!='192.0.2.4' or self.path not in FILES or time.monotonic()>service.deadline:
            self.send_error(403);return
        path=BASE/'pxe'/FILES[self.path]
        size=path.stat().st_size
        with service.lock:
            service.events.append({'path':self.path,'source':self.client_address[0],'bytes':size})
            save(BASE/'pxe-transfers.json',service.events)
        self.send_response(200);self.send_header('Content-Length',str(size));self.end_headers()
        try:
            with path.open('rb') as source:
                while chunk:=source.read(256*1024): self.wfile.write(chunk)
        except (BrokenPipeError,ConnectionResetError): pass

def main():
    # The garden's fixed policy opens provisioning only after both offshoots are ready.
    deadline=time.monotonic()+300
    while not (BASE/'pxe-open').exists():
        if time.monotonic()>deadline: raise TimeoutError('Mother did not open the PXE window')
        time.sleep(.2)
    config=json.loads((BASE/'lan-config.json').read_text())
    path=Path('/run/pxe-dnsmasq.conf');path.write_text(dnsmasq_config(config['test_case']))
    server=http.server.ThreadingHTTPServer(('192.0.2.1',8080),BootHTTP)
    server.daemon_threads=True;server.events=[];server.lock=threading.Lock();server.deadline=time.monotonic()+360
    threading.Thread(target=server.serve_forever,daemon=True).start()
    with (BASE/'pxe-dhcp.log').open('wb') as log:
        child=subprocess.Popen(['/usr/sbin/dnsmasq','--keep-in-foreground','--conf-file='+str(path)],
            stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT)
        try:
            time.sleep(.3)
            if child.poll() is not None: raise RuntimeError('Private PXE DHCP service failed')
            save(BASE/'pxe-ready',{'ready':True})
            print('PXE_SERVICE_READY',flush=True)
            while time.monotonic()<server.deadline:
                if child.poll() is not None: raise RuntimeError('Private PXE DHCP service stopped')
                time.sleep(1)
        finally:
            if child.poll() is None: child.terminate();child.wait(5)
            server.shutdown();server.server_close()

if __name__=='__main__': main()
