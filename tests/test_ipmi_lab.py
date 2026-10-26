"""Actual upstream RMCP+ across processes; backend scope checked independently."""
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]

PROBE = r'''
import json,sys,tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4
root=Path(sys.argv[1]);sys.path.insert(0,str(root/'src'))
from agenticvm.ipmi_lab import OwnedBMC,NativeVM
with tempfile.TemporaryDirectory() as temporary:
    folder=Path(temporary);seed=folder/'configuration.iso';seed.write_bytes(b'approved config')
    vm=SimpleNamespace(uuid=str(uuid4()),boot=0,process=None)
    launches=[]
    def start(target,*,seed=None):
        assert target is vm
        launches.append(seed)
        vm.boot+=1;vm.process=SimpleNamespace(poll=lambda:None)
    def shutdown(target):
        assert target is vm
        vm.process=None
    with patch.object(NativeVM,'start',side_effect=start),patch.object(NativeVM,'poweroff',side_effect=shutdown):
        bmc=OwnedBMC(vm,seed)
        try:
            status=bmc.request('status')
            assert status['authentication_type']==6 and status['privacy']=='aes'
            bad={'port':bmc.port,'password':bmc.password,'uuid':str(uuid4()),'operation':'on'}
            child=__import__('subprocess').run([sys.executable,'-I','-B',str(root/'scripts/ipmi-owned-client.py')],input=json.dumps(bad),text=True,capture_output=True,timeout=15)
            assert child.returncode and not launches
            bmc.request('boot-disk');bmc.request('on');bmc.request('softoff');bmc.request('boot-disk');bmc.request('on')
            assert launches==[seed,None]
            assert not bmc.errors and bmc.serversocket.getsockname()[0]=='::1'
            print(json.dumps({'passed':True,'actual_authenticated_protocol':True,'backend_native_vm_tested':False,'launches':len(launches)}))
        finally:
            bmc.close()
'''


class IPMIContractTests(unittest.TestCase):
    def test_authenticated_wire_binds_uuid_and_passes_only_two_approved_boots(self):
        child = subprocess.run([sys.executable, '-I', '-B', '-c', PROBE, str(ROOT)],
                               text=True, capture_output=True, timeout=35)
        self.assertEqual(child.returncode, 0, child.stdout + child.stderr)
        self.assertIn('"actual_authenticated_protocol": true', child.stdout)
        self.assertIn('"backend_native_vm_tested": false', child.stdout)


if __name__ == '__main__':
    unittest.main()
