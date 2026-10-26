"""Existing garden's network-boot enrollment policy; no SSH and no target shell."""
from __future__ import annotations
import hashlib,json,os,sys,threading,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from lan_agent import Node,Handler,SecureServer,BASE,MEMBERS,ADDRESSES,save

class PXEHandler(Handler):
    def handle_request(self,body):
        node=self.server.node
        if self.server.control and self.path.startswith('/pxe/'):
            try:
                if self.client_address[0]!='192.0.2.4' or node.enrollment is None or time.monotonic()>node.enrollment:
                    raise ValueError('PXE provisioning is not open for this target')
                if self.path=='/pxe/config' and body is None:
                    cfg={key:node.config[key] for key in ('garden','request_id','grant','manifest_sha256','mother_certificate')}
                    cfg.update(identity='sprout-4',mother='https://192.0.2.1:8443')
                    if node.config['test_case']=='wrong-grant': cfg['grant']='deliberately-invalid-lab-grant'
                    return self.output(cfg)
                if self.path=='/pxe/installer' and body is None:
                    raw=(BASE/'lab/lan_install.py').read_bytes()
                    if node.config['test_case']=='bad-bootstrap': raw+=b'\n# deliberate integrity failure\n'
                    self.send_response(200);self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw);return
                if self.path=='/pxe/receipt' and body is not None:
                    if set(body)!={'request_id','identity','grant','receipt'}: raise ValueError('Unknown receipt fields')
                    node.admit(self.client_address[0],{key:body[key] for key in ('request_id','identity','grant')})
                    with node.lock:
                        if node.install_receipt and node.install_receipt!=body['receipt']: raise ValueError('Changed installation receipt')
                        node.install_receipt=body['receipt']
                    return self.output({'ok':True})
                raise ValueError('Unknown PXE endpoint')
            except Exception as error: return self.output({'error':type(error).__name__+': '+str(error)},403)
        return super().handle_request(body)

class PXENode(Node):
    def __init__(self,config): super().__init__(config);self.install_receipt=None
    def start_server(self,port,control=False):
        server=SecureServer((ADDRESSES[self.identity],port),PXEHandler)
        server.node=self;server.control=control;self.servers.append(server)
        threading.Thread(target=server.serve_forever,daemon=True).start()
    def mother(self):
        self.wait_ready(('offshoot-1','offshoot-2'))
        baseline=[self.exchange(name) for name in ('offshoot-1','offshoot-2')]
        self.enrollment=time.monotonic()+400
        (BASE/'pxe-open').write_text('one fixed authorized MAC\n')
        print('PXE_ENROLLMENT_WINDOW_OPEN',flush=True)
        deadline=time.monotonic()+15
        while not (BASE/'pxe-ready').exists():
            if time.monotonic()>deadline: raise TimeoutError('Mother PXE service failed to start')
            time.sleep(.2)
        print('PXE_BOOT_SERVICE_READY',flush=True)
        started=time.monotonic();deadline=started+330
        while time.monotonic()<deadline:
            with self.lock: joined='sprout-4' in self.known;receipt=self.install_receipt
            if joined and receipt:
                try:
                    if self.rpc('sprout-4','/status',timeout=3)[0]['ready']: break
                except OSError: pass
            time.sleep(1)
        else: raise TimeoutError('Network-boot target did not enroll and become model-ready')
        if receipt['ssh_present'] or not receipt['ok']: raise ValueError('Target unexpectedly needed SSH')
        joined_exchange=self.exchange('sprout-4')
        deadline=time.monotonic()+150
        while time.monotonic()<deadline:
            if len(self.rpc('sprout-4','/status')[0]['delivered'])==2: break
            time.sleep(1)
        else: raise TimeoutError('PXE sprout did not exchange messages with both offshoots')
        begin=time.monotonic();before={name:self.rpc(name,'/status')[0] for name in MEMBERS if name!='mother'}
        while time.monotonic()-begin<60: time.sleep(1)
        statuses={name:self.rpc(name,'/status')[0] for name in MEMBERS if name!='mother'}
        statuses['mother']=self.snapshot()
        for name,old in before.items():
            for peer in MEMBERS:
                if peer!=name and statuses[name]['heartbeat_received'].get(peer,0)<=old['heartbeat_received'].get(peer,0):
                    raise ValueError('Encrypted contact did not continue')
        transfers=json.loads((BASE/'pxe-transfers.json').read_text())
        if set(row['path'] for row in transfers)!={'/boot.ipxe','/vmlinuz','/initrd.gz'}:
            raise ValueError('Network boot image transfers are missing')
        report={'passed':True,'schema':'agenticvm.pxe.guest.v1','garden':self.config['garden'],
            'statuses':statuses,'installed':receipt['installed'],'duplicate':receipt['duplicate'],
            'target_receipt':receipt,'baseline':baseline,'joined_exchange':joined_exchange,
            'boot_transfers':transfers,'idle_contact_seconds':round(time.monotonic()-begin,3),
            'enrollment_and_contact_seconds':round(time.monotonic()-started,3),
            'strict_zero_preparation_satisfied':False,'prerequisite':'network-boot firmware and trusted private PXE network',
            'ssh_used':False,'initial_boot_authenticated':False}
        save(BASE/'lan-report.json',report);os.sync()

def main():
    node=None
    try:
        node=PXENode(json.loads((BASE/'lan-config.json').read_text()));node.run()
    except Exception as error:
        save(BASE/'lan-report.json',{'passed':False,'error':type(error).__name__+': '+str(error)})
        import traceback;traceback.print_exc()
        while True: time.sleep(30)

if __name__=='__main__': main()
