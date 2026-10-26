"""Trust boundaries for the local-model game-building loop."""
import importlib.util
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch

from agenticvm import peer_protocol

ROOT=Path(__file__).resolve().parents[1]
fake=types.ModuleType('peer_agent')
fake.FDTransport=object
fake.Evidence=object
before=list(sys.path)
try:
    with patch.dict(sys.modules,{'peer_protocol':peer_protocol,'peer_agent':fake}):
        spec=importlib.util.spec_from_file_location('pong_agent_under_test',ROOT/'guest/pong_agent.py')
        agent=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(agent)
finally:
    sys.path[:]=before


class PongAgentBoundaries(unittest.TestCase):
    def test_arithmetic_expressions_accept_only_small_numeric_vocabulary(self):
        for value in ('position + velocity * dt','-velocity','Math.max(low, Math.min(high, value))'):
            self.assertEqual(agent.expression(value),value)
        for value in ('globalThis.fetch(velocity)','Math.max.constructor(velocity)','while(true){}',
                      '__proto__','value; process.exit()','"secret"','NaN',None,'x'*181):
            with self.subTest(value=value),self.assertRaises(ValueError):agent.expression(value)

    def test_codegen_requires_exact_function_inventory(self):
        formulas={'advance':'position+velocity*dt','bounce':'-velocity','clamp':'Math.max(low,Math.min(high,value))'}
        result=agent.logic_source(formulas)
        self.assertIn('advance:function(position,velocity,dt)',result)
        self.assertIn('bounce:function(velocity)',result)
        with self.assertRaises(ValueError):agent.logic_source({**formulas,'extra':'value'})
        with self.assertRaises(ValueError):agent.logic_source({'bounce':'-velocity'})

    def test_malformed_artifact_inventory_is_rejected_before_filesystem_access(self):
        for files in ({'../../outside':'value'},None,{'index.html':'x'*15000}):
            with self.subTest(files=type(files).__name__),self.assertRaises(ValueError):agent.receive_artifacts(files)

    def test_response_cannot_acknowledge_another_task(self):
        class Channel:
            def send(self,*args,**kwargs):return {'id':'sent-task'}
            def receive(self,**kwargs):return {'kind':'response','reply_to':'different-task','body':{}}
        with self.assertRaisesRegex(ValueError,'correlation'):agent.rpc(Channel(),{'op':'build_pong'},lambda _:None)

    def test_valid_response_returns_only_after_correlated_acknowledgement(self):
        records=[]
        class Channel:
            def send(self,*args,**kwargs):return {'id':'sent-task'}
            def receive(self,**kwargs):return {'id':'reply','kind':'response','reply_to':'sent-task','body':{'checks':{'passed':False}}}
        result=agent.rpc(Channel(),{'op':'build_pong'},records.append)
        self.assertFalse(result['checks']['passed'])
        self.assertEqual([row['event'] for row in records],['task_sent','task_result'])


class GuestKeyCleanupTests(unittest.TestCase):
    def test_exact_generated_key_is_removed_before_sync(self):
        spec=importlib.util.spec_from_file_location('pong_runner_cleanup_test',ROOT/'scripts/run-pong-agents.py')
        runner=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)
        calls=[]
        class VM:
            def run(self,*argv):
                calls.append(argv)
                return '{"private_key_removed":true}' if argv[0]=='/usr/bin/python3' else ''
        self.assertTrue(runner.erase_generated_guest_key(VM())['private_key_removed'])
        self.assertIn("/workspace/peer/key.pem",calls[0][-1])
        self.assertEqual(calls[1],('/bin/sync',))

    def test_unverified_key_cleanup_is_a_failure(self):
        spec=importlib.util.spec_from_file_location('pong_runner_cleanup_failure',ROOT/'scripts/run-pong-agents.py')
        runner=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)
        class VM:
            def run(self,*argv):return '{"private_key_removed":false}'
        with self.assertRaises(RuntimeError):runner.erase_generated_guest_key(VM())


if __name__=='__main__':unittest.main()
