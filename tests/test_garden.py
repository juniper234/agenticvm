import copy
import socket
import threading
import time
import unittest

from agenticvm.garden_wire import Decoder,Multiplexer,MAX_CHUNK,MAX_QUEUED,packet
from agenticvm.garden import HealthTracker,inspect_status,original_pair_continued


class SocketRaw:
    def __init__(self,sock):
        self.sock = sock
    def read(self,size,timeout):
        self.sock.settimeout(timeout)
        return self.sock.recv(size)
    def write(self,data,timeout):
        self.sock.settimeout(timeout)
        self.sock.sendall(data)
    def close(self):
        self.sock.close()


class GardenWireTests(unittest.TestCase):
    def test_partial_and_coalesced_frames_route_independently(self):
        decoder = Decoder()
        content = packet(2,b'first')+packet(3,b'second')
        self.assertEqual(decoder.feed(content[:3]),[])
        self.assertEqual(decoder.feed(content[3:]),[(2,b'first'),(3,b'second')])

    def test_invalid_headers_and_oversize_are_refused_before_allocation(self):
        for content in (b'\x00\0\0\0\x01',b'\x09\0\0\0\x01',b'\x01\0\x10\0\0',b'\x02\0\0\0\0'):
            with self.assertRaises(ValueError):
                Decoder().feed(content)
        with self.assertRaises(ValueError):
            packet(1,b'x'*(MAX_CHUNK+1))

    def test_all_eight_channels_decode(self):
        decoder = Decoder()
        frames = b''.join(packet(channel,bytes([channel])) for channel in range(1,9))
        self.assertEqual(decoder.feed(frames),[(channel,bytes([channel])) for channel in range(1,9)])

    def test_actual_socket_channels_stay_separate_and_one_close_preserves_other(self):
        left,right = socket.socketpair()
        mux = Multiplexer(SocketRaw(left),1)
        try:
            right.sendall(packet(2,b'from two')+packet(3,b'from three'))
            two,three = mux.channel(2),mux.channel(3)
            self.assertEqual(three.read(100,1),b'from three')
            two.close()
            self.assertEqual(two.read(100,1),b'from two')
            three.write(b'reply',1)
            self.assertEqual(Decoder().feed(right.recv(100)),[(3,b'reply')])
        finally:
            mux.close()
            right.close()

    def test_missing_logical_data_has_a_deadline(self):
        left,right = socket.socketpair()
        mux = Multiplexer(SocketRaw(left),1)
        try:
            with self.assertRaises(TimeoutError):
                mux.channel(2).read(10,.02)
            with self.assertRaises(ValueError):
                mux.channel(1)
        finally:
            mux.close()
            right.close()

    def test_congested_unconsumed_peer_fails_closed(self):
        left,right = socket.socketpair()
        mux = Multiplexer(SocketRaw(left),1)
        try:
            for _ in range(MAX_QUEUED//MAX_CHUNK+1):
                right.sendall(packet(2,b'x'*MAX_CHUNK))
            self.assertTrue(mux.stopped.wait(2))
            self.assertIn('congested',mux.error)
        finally:
            mux.close()
            right.close()

    def test_verification_requires_all_six_validated_pinned_tls_directions(self):
        identities = {i:{'sha256':str(i)*64} for i in (1,2,3)}
        status = {str(i):{'interfaces':['lo'],'errors':[],'wire_error':None,'running':True,'heartbeat_sequence':1,'updated_unix_ms':int(time.time()*1000),'links':{
            str(j):{'connected':True,'received_verified':5,'state':{'sent':5,'received':5,'acked':5},
                    'tls':{'tls':'TLSv1.3','alpn':'agenticvm-garden/1','peer_cert_sha256':identities[j]['sha256']}}
            for j in (1,2,3) if i != j}} for i in (1,2,3)}
        self.assertTrue(inspect_status(status,identities,(1,2,3)))
        for field,value in (('received_verified',0),('connected',False)):
            changed = copy.deepcopy(status)
            changed['3']['links']['1'][field] = value
            self.assertFalse(inspect_status(changed,identities,(1,2,3)))
        changed = copy.deepcopy(status)
        changed['1']['links']['3']['tls']['peer_cert_sha256'] = '0'*64
        self.assertFalse(inspect_status(changed,identities,(1,2,3)))
        changed = copy.deepcopy(status)
        changed['2']['heartbeat_sequence'] = 0
        self.assertFalse(inspect_status(changed,identities,(1,2,3)))
        changed = copy.deepcopy(status)
        changed['2']['running'] = False
        self.assertFalse(inspect_status(changed,identities,(1,2,3)))

    def test_health_detects_stale_status_and_rollback_without_synchronized_clocks(self):
        tracker = HealthTracker()
        current = {'1':{'heartbeat_sequence':1,'running':True,'updated_unix_ms':999999999999999}}
        self.assertTrue(tracker.observe(current,now=100))
        self.assertTrue(tracker.observe(current,now=109))
        self.assertFalse(tracker.observe(current,now=110))
        current['1']['heartbeat_sequence'] = 2
        current['1']['updated_unix_ms'] = 0
        self.assertTrue(tracker.observe(current,now=111))
        current['1']['heartbeat_sequence'] = 1
        self.assertFalse(tracker.observe(current,now=112))

    def test_idle_model_pair_continues_with_heartbeats_without_extra_completions(self):
        before = {str(i):{'links':{str(j):{'connected':True,'connections':1,'state':{'received':2},
                  'events':{'heartbeat_received':3,'heartbeat_acknowledged':2}}}}
                  for i,j in ((1,2),(2,1))}
        after = copy.deepcopy(before)
        for i,j in (('1','2'),('2','1')):
            after[i]['links'][j]['events']['heartbeat_received'] += 20
        self.assertTrue(original_pair_continued(before,after,lfm=True))
        self.assertFalse(original_pair_continued(before,after,lfm=False))
        self.assertFalse(original_pair_continued(before,before,lfm=True))
        after['1']['links']['2']['connections'] = 2
        self.assertFalse(original_pair_continued(before,after,lfm=True))


if __name__ == '__main__':
    unittest.main()
