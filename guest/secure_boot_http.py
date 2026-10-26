"""Private boot server for a complete firmware-allowlisted UKI, never a shell."""
import http.server,sys,threading,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import independent_boot_server as original
original.FILES.clear();original.FILES.update({'/boot.ipxe':'boot.ipxe','/garden.efi':'garden.efi'})
from independent_boot_server import BootHTTP,save,BASE
def main():
    server=http.server.ThreadingHTTPServer(('192.0.2.1',8080),BootHTTP)
    server.daemon_threads=True;server.events=[];server.lock=threading.Lock();server.deadline=time.monotonic()+600
    threading.Thread(target=server.serve_forever,daemon=True).start()
    save(BASE/'pxe-ready',{'ready':True,'serves_allowlisted_uki':True})
    print('SECURE_UKI_HTTP_READY',flush=True)
    while time.monotonic()<server.deadline: time.sleep(1)
    server.shutdown();server.server_close()
if __name__=='__main__': main()
