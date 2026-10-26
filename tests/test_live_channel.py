"""Host tests: durable live state, hostile frames, and a real blind TCP relay."""
from contextlib import closing
import hashlib
import json
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from uuid import uuid4

from agenticvm.live_channel import Mailbox,Frames,InvalidLiveFrame,MAX_FRAME
from agenticvm import live_bridge as bridge


class LiveMailboxTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root,self.run_id = Path(self.temp.name),str(uuid4())
        self.a = Mailbox(self.root/'a.sqlite',self.run_id,'a','b')
        self.b = Mailbox(self.root/'b.sqlite',self.run_id,'b','a')

    def tearDown(self):
        self.a.close()
        self.b.close()
        self.temp.cleanup()

    def data(self,row):
        return {'seq':row['seq'],'id':row['id'],'payload':json.loads(row['payload']),'digest':row['digest']}

    def test_full_duplex_durable_delivery_and_reconnect_reconciles_lost_ack(self):
        a = self.a.enqueue({'text':'from a \u4f60\u597d'})
        b = self.b.enqueue({'text':'from b'})
        self.assertTrue(self.b.accept(self.data(a)))
        self.assertTrue(self.a.accept(self.data(b)))
        self.b.close()
        self.b = Mailbox(self.root/'b.sqlite',self.run_id,'b','a')
        self.a.synchronize(self.b.state())
        self.b.synchronize(self.a.state())
        self.assertEqual(self.a.pending(0),[])
        self.assertEqual(self.a.state(),{'sent':1,'received':1,'acked':1})
        self.assertFalse(self.b.accept(self.data(a)))

    def test_replayed_sequence_changed_digest_id_or_payload_cannot_change_inbox(self):
        row = self.data(self.a.enqueue({'text':'original'}))
        self.b.accept(row)
        for changed in ({**row,'id':str(uuid4())},{**row,'payload':{'text':'changed'}},{**row,'digest':'0'*64}):
            with self.assertRaises(InvalidLiveFrame):
                self.b.accept(changed)
        self.assertEqual(self.b.state()['received'],1)

    def test_sequence_gap_and_impossible_acknowledgements_fail_closed(self):
        row = self.data(self.a.enqueue({'x':1}))
        with self.assertRaises(InvalidLiveFrame):
            self.b.accept({**row,'seq':2})
        with self.assertRaises(InvalidLiveFrame):
            self.a.acknowledge(2)
        self.a.acknowledge(1)
        with self.assertRaises(InvalidLiveFrame):
            self.a.acknowledge(0)

    def test_durable_state_rollback_or_wrong_identity_cannot_resume(self):
        row = self.data(self.a.enqueue({'x':1}))
        self.b.accept(row)
        self.a.acknowledge(1)
        with self.assertRaises(InvalidLiveFrame):
            self.a.synchronize({'sent':0,'received':0,'acked':0})
        with self.assertRaises(InvalidLiveFrame):
            self.b.synchronize({'sent':0,'received':0,'acked':0})
        with self.assertRaises(ValueError):
            Mailbox(self.root/'a.sqlite',str(uuid4()),'a','b')

    def test_producer_uuid_is_idempotent_after_restart_and_changed_reuse_fails(self):
        identifier = str(uuid4())
        first = self.a.enqueue({'x':1},identifier)
        self.a.close()
        self.a = Mailbox(self.root/'a.sqlite',self.run_id,'a','b')
        self.assertEqual(self.a.enqueue({'x':1},identifier)['seq'],first['seq'])
        with self.assertRaises(InvalidLiveFrame):
            self.a.enqueue({'x':2},identifier)

    def test_backpressure_does_not_drop_or_overwrite_pending_work(self):
        with patch('agenticvm.live_channel.MAX_PENDING',2):
            self.a.enqueue({'x':1})
            self.a.enqueue({'x':2})
            with self.assertRaises(BufferError):
                self.a.enqueue({'x':3})
            self.assertEqual(len(self.a.pending(0)),2)
            self.a.acknowledge(1)
            self.assertEqual(self.a.enqueue({'x':3})['seq'],3)

    def test_frame_replay_oversize_wrong_run_and_partial_timeout(self):
        class Stream:
            def __init__(self):
                self.content = bytearray()
            def write(self,data,timeout):
                self.content.extend(data)
            def read(self,size,timeout):
                if not self.content:
                    raise TimeoutError()
                take = min(size,3)
                result = bytes(self.content[:take])
                del self.content[:take]
                return result
        stream = Stream()
        sender,reader = Frames(stream,self.a),Frames(stream,self.b)
        sender.send('ping',{'nonce':str(uuid4())})
        original = bytes(stream.content)
        self.assertEqual(reader.receive(1)['kind'],'ping')
        stream.content.extend(original)
        with self.assertRaises(InvalidLiveFrame):
            reader.receive(1)
        with self.assertRaises(InvalidLiveFrame):
            Frames(type('Bad',(),{'read':lambda *args:struct.pack('!I',MAX_FRAME+1)})(),self.b).receive(1)
        stream.content = bytearray(original[:7])
        partial = Frames(stream,self.b)
        with self.assertRaises(TimeoutError):
            partial.receive(.01)
        stream.content.extend(original[7:])
        self.assertEqual(partial.receive(1)['wire'],1)
        value = json.loads(original[4:])
        value['run'] = str(uuid4())
        content = json.dumps(value).encode()
        stream.content = bytearray(struct.pack('!I',len(content))+content)
        with self.assertRaises(InvalidLiveFrame):
            Frames(stream,self.b).receive(1)

    def test_boolean_counters_extra_fields_and_oversize_payloads_fail(self):
        for sequence in (True,-1,2**54):
            with self.assertRaises(InvalidLiveFrame):
                self.a.acknowledge(sequence)
        with self.assertRaises(InvalidLiveFrame):
            self.a.enqueue({'text':'x'*16384})
        with self.assertRaises(InvalidLiveFrame):
            self.a.synchronize({'sent':0,'received':0,'acked':0,'command':'exec'})

    def test_retention_preserves_high_water_marks_and_never_replays_consumed_data(self):
        first = None
        with patch('agenticvm.live_channel.MAX_RECORDS',12):
            for index in range(60):
                row = self.data(self.a.enqueue({'x':index}))
                first = first or row
                self.b.accept(row)
                self.a.acknowledge(row['seq'])
                self.b.consume(row['seq'])
                self.a.prune(keep=2)
                self.b.prune(keep=2)
        self.assertEqual(self.a.state()['sent'],60)
        self.assertEqual(self.b.state()['received'],60)
        self.assertEqual(self.b.incoming(),[])
        self.assertFalse(self.b.accept(first))
        self.assertLessEqual(self.b._records(),2)
        self.b.close()
        self.b = Mailbox(self.root/'b.sqlite',self.run_id,'b','a')
        self.assertEqual(self.b.state()['received'],60)
        self.a.synchronize(self.b.state())

    def test_retention_cannot_remove_pending_messages_or_unconsumed_inbox(self):
        for index in range(8):
            row = self.data(self.a.enqueue({'x':index}))
            self.b.accept(row)
        self.a.prune(keep=1)
        self.b.prune(keep=1)
        self.assertEqual(self.a._records(),8)
        self.assertEqual(len(self.b.incoming()),8)
        with self.assertRaises(InvalidLiveFrame):
            self.b.consume(9)

    def test_process_crash_during_receive_leaves_no_half_committed_delivery(self):
        data = self.data(self.a.enqueue({'event':'durable'}))
        source = self.root/'incoming.json'
        source.write_text(json.dumps(data))
        code = """
import json,os,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from agenticvm.live_channel import Mailbox
box=Mailbox(sys.argv[2],sys.argv[3],'b','a')
box.db.create_function('crash_now',0,lambda:os._exit(23))
box.db.execute('CREATE TEMP TRIGGER test_crash AFTER INSERT ON incoming BEGIN SELECT crash_now(); END')
box.accept(json.loads(Path(sys.argv[4]).read_text()))
"""
        child = subprocess.run([sys.executable,'-I','-B','-c',code,
            str(Path(__file__).resolve().parents[1]/'src'),str(self.root/'b.sqlite'),self.run_id,str(source)],
            capture_output=True,timeout=15)
        self.assertEqual(child.returncode,23,child.stderr)
        self.assertEqual(self.b.state()['received'],0)
        self.assertEqual(self.b.incoming(),[])
        self.assertTrue(self.b.accept(data))
        self.assertFalse(self.b.accept(data))


class BlindLiveRelayTests(unittest.TestCase):
    def setUp(self):
        self.service = bridge.Relay()
        self.thread = threading.Thread(target=self.service.serve_forever,daemon=True)
        self.thread.start()
        self.sockets = []

    def tearDown(self):
        for sock in self.sockets:
            bridge.close_socket(sock)
        self.service.stop()
        self.thread.join(3)

    def pair(self,room=None):
        room = room or str(uuid4())
        result,errors = [],[]
        def first():
            try:
                result.append(bridge.join('127.0.0.1',self.service.server_address[1],room,'a'))
            except Exception as error:
                errors.append(error)
        thread = threading.Thread(target=first,daemon=True)
        thread.start()
        second = bridge.join('127.0.0.1',self.service.server_address[1],room,'b')
        thread.join(3)
        self.assertEqual(errors,[])
        self.assertEqual(len(result),1)
        self.sockets.extend([result[0],second])
        for sock in self.sockets:
            sock.settimeout(2)
        return result[0],second

    def test_real_relay_is_continuous_full_duplex_and_honors_disconnect(self):
        a,b = self.pair()
        for index in range(40):
            left,right = ('a:'+str(index)).encode(),('b:'+str(index)).encode()
            a.sendall(left)
            b.sendall(right)
            self.assertEqual(b.recv(100),left)
            self.assertEqual(a.recv(100),right)
        self.service.disconnect_all()
        self.assertEqual(a.recv(100),b'')

    def test_independent_rooms_do_not_cross_streams(self):
        a,b = self.pair()
        c,d = self.pair()
        a.sendall(b'room-one')
        c.sendall(b'room-two')
        self.assertEqual(b.recv(100),b'room-one')
        self.assertEqual(d.recv(100),b'room-two')

    def test_malformed_preface_and_oversize_header_are_rejected(self):
        for content in (b'{"v":1,"room":"../x","side":"a"}\n',b'x'*257):
            with socket.create_connection(self.service.server_address,timeout=2) as sock:
                sock.settimeout(2)
                sock.sendall(content)
                try:
                    self.assertEqual(sock.recv(100),b'')
                except ConnectionResetError:
                    pass


if __name__ == '__main__':
    unittest.main()
