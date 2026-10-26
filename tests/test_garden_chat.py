"""Application tests use an explicit fake generator; native LFM proof is separate."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from uuid import uuid4

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'guest'))
from garden_chat import Chat,prompt_for
from local_lfm import MODEL_SHA,MODEL_NAME
from agenticvm.garden_model import verify_conversation


class FakeModel:
    def __init__(self,fail=False):
        self.fail = fail
        self.prompts = []
    def start(self):
        pass
    def generate(self,prompt):
        if self.fail:
            raise RuntimeError('injected model failure')
        self.prompts.append(prompt)
        text = 'Unit test output '+str(len(self.prompts))
        return {'text':text,'raw_content':json.dumps({'text':text}),'completion_tokens':8,
                'text_sha256':hashlib.sha256(text.encode()).hexdigest(),
                'prompt_sha256':hashlib.sha256(prompt.encode()).hexdigest(),'seconds':0,'timings':{}}
    def snapshot(self):
        return {'fake_generator_for_unit_tests':True}
    def close(self):
        pass


class GardenChatTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.garden = str(uuid4())
        self.chats = []
    def tearDown(self):
        for chat in self.chats:
            chat.close()
        self.temp.cleanup()
    def make(self,member,**kwargs):
        chat = Chat(Path(self.temp.name)/(str(member)+'.sqlite'),self.garden,member,**kwargs)
        self.chats.append(chat)
        return chat
    def wait(self,chat,peer,count):
        deadline = time.monotonic()+3
        while time.monotonic()<deadline:
            result = chat.peer_snapshot(peer)
            if result['generated_count']>=count:
                return result
            self.assertIsNone(chat.error)
            time.sleep(.01)
        self.fail('Fake model worker did not complete')
    def message(self):
        message = str(uuid4())
        content = 'Hello from a different sprout 你好'
        return {'op':'garden-chat','garden':self.garden,'from':'sprout-2','to':'sprout-1',
                'id':message,'kind':'hello','reply_to':None,'text':content,
                'model':{'name':MODEL_NAME,'weights_sha256':MODEL_SHA,'call_id':message,
                         'text_sha256':hashlib.sha256(content.encode()).hexdigest(),'completion_tokens':12}}
    def test_enrollment_is_idempotent_and_only_generated_output_is_sent(self):
        fake = FakeModel()
        chat = self.make(1,model=fake)
        chat.enroll(2)
        chat.enroll(2)
        chat.start()
        result = self.wait(chat,2,1)
        self.assertEqual(result['generated_count'],1)
        message = chat.pending(2)[0]
        self.assertEqual(message['text'],'Unit test output 1')
        chat.enqueued(message['id'])
        self.assertEqual(chat.pending(2),[])
        self.assertEqual(len(fake.prompts),1)
    def test_incoming_greeting_generates_reply_from_the_actual_text(self):
        fake = FakeModel()
        chat = self.make(1,model=fake)
        original = self.message()
        self.assertTrue(chat.accept(2,original))
        self.assertFalse(chat.accept(2,original))
        chat.start()
        reply = self.wait(chat,2,1)['generated'][0]
        self.assertEqual(reply['kind'],'reply')
        self.assertEqual(reply['reply_to'],original['id'])
        self.assertEqual(fake.prompts,[prompt_for('sprout-1','sprout-2',original)])
        self.assertIn(json.dumps(original['text']),fake.prompts[0])
    def test_changed_duplicate_and_invalid_provenance_do_not_queue_work(self):
        chat = self.make(1,model=FakeModel())
        original = self.message()
        chat.accept(2,original)
        for change in ('text','pin','route'):
            altered = copy.deepcopy(original)
            if change=='text':
                altered['text'] = 'changed'
            elif change=='pin':
                altered['model']['weights_sha256'] = '0'*64
            else:
                altered['to'] = 'sprout-3'
            with self.assertRaises(ValueError):
                chat.accept(2,altered)
        self.assertEqual(chat.db.execute('SELECT COUNT(*) FROM tasks').fetchone()[0],1)
    def test_unsolicited_reply_cannot_claim_a_nonexistent_greeting(self):
        chat = self.make(1,model=FakeModel())
        original = self.message()
        original.update(kind='reply',reply_to=str(uuid4()))
        with self.assertRaises(ValueError):
            chat.accept(2,original)
        self.assertEqual(chat.peer_snapshot(2)['received_count'],0)
    def test_reply_correlates_to_real_outgoing_greeting_and_stops_ping_pong(self):
        left,right = self.make(1,model=FakeModel()),self.make(2,model=FakeModel())
        left.enroll(2)
        left.start()
        right.start()
        greeting = self.wait(left,2,1)['generated'][0]
        right.accept(1,greeting)
        response = self.wait(right,1,1)['generated'][0]
        self.assertTrue(left.accept(2,response))
        self.assertFalse(left.accept(2,response))
        self.assertEqual(left.db.execute('SELECT COUNT(*) FROM tasks').fetchone()[0],1)
        self.assertEqual(left.peer_snapshot(2)['received_reply'],1)
    def test_model_failure_has_no_canned_success_fallback(self):
        chat = self.make(1,model=FakeModel(fail=True))
        chat.enroll(2)
        chat.start()
        until = time.monotonic()+2
        while chat.error is None and time.monotonic()<until:
            time.sleep(.01)
        self.assertIsNotNone(chat.error)
        self.assertEqual(chat.pending(2),[])
    def test_generation_checkpoint_is_not_silently_replayed(self):
        chat = self.make(1,model=FakeModel())
        chat.enroll(2)
        with chat.db:
            chat.db.execute("UPDATE tasks SET state='generating'")
        path = Path(self.temp.name)/'1.sqlite'
        with self.assertRaises(ValueError):
            Chat(path,self.garden,1,model=FakeModel())

    def test_three_application_ledgers_reconcile_and_changed_completion_fails(self):
        chats = {i:self.make(i,model=FakeModel()) for i in (1,2,3)}
        for i,chat in chats.items():
            for j in chats:
                if i!=j:
                    chat.enroll(j)
            chat.start()
        end = time.monotonic()+3
        while time.monotonic()<end:
            for i,chat in chats.items():
                for j,recipient in chats.items():
                    if i!=j:
                        for message in chat.pending(j):
                            recipient.accept(i,message)
                            chat.enqueued(message['id'])
            if all(c.db.execute("SELECT COUNT(*) FROM tasks WHERE state='complete'").fetchone()[0]==4 for c in chats.values()) and all(
                    c.peer_snapshot(j)['received_count']==2 for i,c in chats.items() for j in chats if i!=j):
                break
            time.sleep(.01)
        snapshots = {str(i):{'model':chat.snapshot(),'links':{str(j):{'application':chat.peer_snapshot(j)} for j in chats if i!=j}}
                     for i,chat in chats.items()}
        self.assertTrue(all(verify_conversation(snapshots).values()))
        snapshots['1']['model']['calls'][0]['text'] = 'silently changed'
        with self.assertRaises(ValueError):
            verify_conversation(snapshots)


if __name__ == '__main__':
    unittest.main()
