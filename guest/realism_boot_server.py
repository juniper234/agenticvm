"""Mother serves boot files; a different VM handles DHCP and TFTP."""
import http.server,json,sys,threading,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from independent_boot_server import BootHTTP,save,BASE
import independent_boot_server
independent_boot_server.FILES['/ipxe.efi']='ipxe.efi'

def main():
    deadline=time.monotonic()+300
    while not (BASE/'pxe-open').exists():
        if time.monotonic()>deadline: raise TimeoutError('Mother never opened enrollment')
        time.sleep(.2)
    server=http.server.ThreadingHTTPServer(('192.0.2.1',8080),BootHTTP)
    server.daemon_threads=True;server.events=[];server.lock=threading.Lock();server.deadline=time.monotonic()+600
    threading.Thread(target=server.serve_forever,daemon=True).start()
    save(BASE/'pxe-ready',{'ready':True,'dhcp_hosted_here':False})
    print('REALISM_BOOT_HTTP_READY',flush=True)
    while time.monotonic()<server.deadline: time.sleep(1)
    server.shutdown();server.server_close()

if __name__=='__main__': main()
