"""Owned isolated LAN: one dynamically learned boot client; no target MAC preset.

This is normal PXE provisioning on a private simulated network, never an
exploit, physical-LAN DHCP service, scanner or authentication bypass.
"""
import http.server,json,subprocess,threading,time
from pathlib import Path
BASE=Path('/workspace')
FILES={'/boot.ipxe':'boot.ipxe','/vmlinuz':'vmlinuz','/initrd.gz':'initrd.gz'}

def save(path,value):
    tmp=path.with_suffix('.tmp');tmp.write_text(json.dumps(value,sort_keys=True)+'\n');tmp.chmod(0o644);tmp.replace(path)

def dnsmasq_config():
    return '''port=0
interface=eth0
listen-address=192.0.2.1
bind-interfaces
no-resolv
no-hosts
dhcp-authoritative
dhcp-range=192.0.2.4,192.0.2.4,255.255.255.0,2m
dhcp-option=option:router
dhcp-option=option:dns-server
dhcp-boot=http://192.0.2.1:8080/boot.ipxe,,192.0.2.1
dhcp-leasefile=/run/independent.leases
pid-file=/run/independent-dhcp.pid
log-dhcp
log-facility=-
user=root
'''

class BootHTTP(http.server.BaseHTTPRequestHandler):
    def log_message(self,*args): pass
    def do_GET(self):
        service=self.server
        if (self.client_address[0]!='192.0.2.4' or self.path not in FILES or
            time.monotonic()>service.deadline or len(service.events)>=16):
            self.send_error(403);return
        path=BASE/'pxe'/FILES[self.path];size=path.stat().st_size
        with service.lock:
            service.events.append({'path':self.path,'source':self.client_address[0],'bytes':size})
            save(BASE/'pxe-transfers.json',service.events)
        self.send_response(200);self.send_header('Content-Length',str(size));self.end_headers()
        try:
            with path.open('rb') as source:
                while chunk:=source.read(256*1024): self.wfile.write(chunk)
        except (BrokenPipeError,ConnectionResetError): pass

def main():
    deadline=time.monotonic()+300
    while not (BASE/'pxe-open').exists():
        if time.monotonic()>deadline: raise TimeoutError('Mother never opened provisioning')
        time.sleep(.2)
    path=Path('/run/independent-dnsmasq.conf');path.write_text(dnsmasq_config())
    server=http.server.ThreadingHTTPServer(('192.0.2.1',8080),BootHTTP)
    server.daemon_threads=True;server.events=[];server.lock=threading.Lock();server.deadline=time.monotonic()+360
    threading.Thread(target=server.serve_forever,daemon=True).start()
    with (BASE/'pxe-dhcp.log').open('wb') as log:
        child=subprocess.Popen(['/usr/sbin/dnsmasq','--keep-in-foreground','--conf-file='+str(path)],
            stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT)
        try:
            time.sleep(.3)
            if child.poll() is not None: raise RuntimeError('Private DHCP failed')
            save(BASE/'pxe-ready',{'ready':True});print('INDEPENDENT_BOOT_SERVICE_READY',flush=True)
            while time.monotonic()<server.deadline:
                if child.poll() is not None: raise RuntimeError('Private DHCP stopped')
                lease=Path('/run/independent.leases')
                if lease.exists(): save(BASE/'learned-leases.json',{'leases':lease.read_text()})
                time.sleep(1)
        finally:
            if child.poll() is None: child.terminate();child.wait(5)
            server.shutdown();server.server_close()

if __name__=='__main__': main()
