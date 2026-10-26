"""Separate, owned DHCP/TFTP appliance, reachable only on the private lab switch."""
import subprocess,time
from pathlib import Path

def config():
    return '''port=0
interface=eth0
listen-address=192.0.2.5
bind-interfaces
no-resolv
no-hosts
dhcp-authoritative
dhcp-range=192.0.2.4,192.0.2.4,255.255.255.0,2m
dhcp-option=option:router
dhcp-option=option:dns-server
dhcp-match=set:ipxe,175
dhcp-userclass=set:ipxe,iPXE
dhcp-match=set:efi,option:client-arch,7
dhcp-match=set:efi,option:client-arch,9
dhcp-boot=tag:ipxe,http://192.0.2.1:8080/boot.ipxe,,192.0.2.1
dhcp-boot=tag:!ipxe,tag:efi,ipxe.efi,,192.0.2.5
dhcp-boot=tag:!ipxe,tag:!efi,http://192.0.2.1:8080/boot.ipxe,,192.0.2.1
enable-tftp
tftp-root=/bootfiles
tftp-no-fail
dhcp-leasefile=/run/realism.leases
pid-file=/run/realism-dhcp.pid
log-dhcp
log-facility=-
user=root
'''

def main():
    path=Path('/run/realism-dnsmasq.conf');path.write_text(config())
    child=subprocess.Popen(['/usr/sbin/dnsmasq','--keep-in-foreground','--conf-file='+str(path)])
    time.sleep(.5)
    if child.poll() is not None: raise RuntimeError('Separate DHCP failed')
    print('REALISM_DHCP_APPLIANCE_READY',flush=True)
    while child.poll() is None: time.sleep(1)
    raise RuntimeError('Separate DHCP exited')

if __name__=='__main__': main()
