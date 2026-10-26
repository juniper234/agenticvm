"""Mother's finite real-model acceptance with observed network outage/recovery."""
import json,os,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from pxe_agent import PXENode,BASE,MEMBERS,save

class RealisticMother(PXENode):
    def mother(self):
        self.wait_ready(('offshoot-1','offshoot-2'))
        baseline=[self.exchange(name) for name in ('offshoot-1','offshoot-2')]
        self.enrollment=time.monotonic()+600
        (BASE/'pxe-open').write_text('one authorized private-lab target\n')
        deadline=time.monotonic()+20
        while not (BASE/'pxe-ready').exists():
            if time.monotonic()>deadline: raise TimeoutError('HTTP boot service did not start')
            time.sleep(.2)
        print('REALISM_GARDEN_BOOT_SERVICE_READY',flush=True)
        began=time.monotonic();deadline=began+360
        while time.monotonic()<deadline:
            with self.lock: joined='sprout-4' in self.known;receipt=self.install_receipt
            if joined and receipt:
                try:
                    if self.rpc('sprout-4','/status',timeout=3)[0]['ready']: break
                except OSError: pass
            time.sleep(1)
        else: raise TimeoutError('Target did not enroll and become model-ready')
        if receipt['ssh_present'] or not receipt['ok']: raise ValueError('Unexpected SSH or failed installation')
        if self.config['test_case']=='resume' and not any(row['name']=='model.gguf' and row['resumed'] for row in receipt['installed']['downloads']):
            raise ValueError('Deliberate interrupted model transfer did not resume')
        joined_exchange=self.exchange('sprout-4')
        deadline=time.monotonic()+120
        while time.monotonic()<deadline:
            if len(self.rpc('sprout-4','/status')[0]['delivered'])==2: break
            time.sleep(1)
        else: raise TimeoutError('Target did not contact both offshoots')
        before={name:self.rpc(name,'/status')[0] for name in MEMBERS if name!='mother'}
        print('REALISM_CONTACT_FAULT_READY',flush=True)
        seconds=self.config['contact_seconds']
        if type(seconds) is not int or not 60<=seconds<=3600: raise ValueError('Bounded contact window required')
        start=time.monotonic();samples=[];failures=0;recovered=False
        while time.monotonic()-start<seconds:
            try:
                state=self.rpc('sprout-4','/status',timeout=2)[0]
                if state['pid']!=before['sprout-4']['pid'] or state['public_identity']!=before['sprout-4']['public_identity']:
                    raise ValueError('Target identity/process changed across cable interruption')
                if failures: recovered=True
                samples.append({'elapsed':round(time.monotonic()-start,3),'reachable':True,'heartbeats':state['heartbeat_received']})
            except OSError as error:
                failures+=1;samples.append({'elapsed':round(time.monotonic()-start,3),'reachable':False,'error':type(error).__name__})
            time.sleep(2)
        statuses={name:self.rpc(name,'/status',timeout=5)[0] for name in MEMBERS if name!='mother'}
        statuses['mother']=self.snapshot()
        for name,old in before.items():
            for peer in MEMBERS:
                if peer!=name and statuses[name]['heartbeat_received'].get(peer,0)<=old['heartbeat_received'].get(peer,0):
                    raise ValueError('Encrypted heartbeat did not resume for '+name+'/'+peer)
            if [x['id'] for x in statuses[name]['calls']]!=[x['id'] for x in old['calls']]:
                raise ValueError('Unexpected model task replay during cable recovery')
        if self.config['cable_fault'] and (not failures or not recovered):
            raise ValueError('A real outage and recovery were not observed inside the mother')
        transfers=json.loads((BASE/'pxe-transfers.json').read_text())
        expected={'/boot.ipxe','/garden.efi'} if self.config.get('secure_boot') else {'/boot.ipxe','/vmlinuz','/initrd.gz'}
        if not expected<=set(row['path'] for row in transfers):
            raise ValueError('Boot payload transfers missing')
        report={'passed':True,'garden':self.config['garden'],'statuses':statuses,'baseline':baseline,
            'joined_exchange':joined_exchange,'target_receipt':receipt,'boot_transfers':transfers,
            'contact_seconds':round(time.monotonic()-start,3),'contact_samples':samples,
            'network_failures_observed':failures,'recovered_after_network_failure':recovered,
            'target_identity_and_process_preserved':True,'model_tasks_replayed':False,
            'ssh_used':False,'initial_boot_authenticated':bool(self.config.get('secure_boot')),'target_reboot_recovery_tested':False}
        save(BASE/'lan-report.json',report);os.sync()

def main():
    try: RealisticMother(json.loads((BASE/'lan-config.json').read_text())).run()
    except Exception as error:
        save(BASE/'lan-report.json',{'passed':False,'error':type(error).__name__+': '+str(error)})
        import traceback;traceback.print_exc()
        while True: time.sleep(30)

if __name__=='__main__': main()
