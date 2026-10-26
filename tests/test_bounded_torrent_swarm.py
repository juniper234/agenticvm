"""Concurrent private-peer swarm transfer; no discovery or execution."""
import hashlib
from pathlib import Path
import socket
import tempfile
import time
import unittest

from agenticvm.bounded_torrent import Seeder, download, download_swarm, metadata


class SwarmTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix='swarm-', dir=Path(__file__).resolve().parents[1] / 'runtime'))
        self.asset = self.root / 'agent.tar.gz'
        self.asset.write_bytes(b'swarm-data-' * 120_000)  # > four 256 KiB pieces
        self.digest = hashlib.sha256(self.asset.read_bytes()).hexdigest()
        self.entry = {'bytes': self.asset.stat().st_size, 'sha256': self.digest,
                      'torrent': metadata(self.asset)}
        self.seeds = []
        for _ in range(2):
            seed = Seeder({'agent.tar.gz': (self.asset, self.entry)}, ('127.0.0.1', 0), '127.0.0.1')
            self.seeds.append(seed)

    def tearDown(self):
        for seed in self.seeds:
            seed.close()
        import shutil
        shutil.rmtree(self.root, ignore_errors=True)

    def test_download_survives_more_than_sixteen_prior_connections(self):
        seed = self.seeds[0]
        for _ in range(16):
            sock = socket.create_connection(seed.address, timeout=2)
            sock.close()
        deadline = time.monotonic() + 5
        while seed.stats['connections'] < 16 and time.monotonic() < deadline:
            time.sleep(.02)
        destination = self.root / 'after-sixteen.tar.gz'
        result = download(self.entry['torrent'], destination, name='agent.tar.gz',
                          size=self.entry['bytes'], sha256=self.digest,
                          source=seed.address, attempts=1)
        self.assertTrue(result['sha256_verified'])
        self.assertEqual(seed.stats['connections'], 17)
        self.assertEqual(destination.read_bytes(), self.asset.read_bytes())

    def test_two_peers_both_contribute_and_hash_verifies(self):
        destination = self.root / 'out.tar.gz'
        result = download_swarm(self.entry['torrent'], destination, name='agent.tar.gz',
                                size=self.entry['bytes'], sha256=self.digest,
                                sources=[seed.address for seed in self.seeds])
        self.assertTrue(result['sha256_verified'])
        self.assertTrue(result['swarm'])
        self.assertEqual(result['peer_count'], 2)
        self.assertEqual(destination.read_bytes(), self.asset.read_bytes())
        self.assertTrue(all(value > 0 for value in result['peer_bytes'].values()), result)
        self.assertTrue(all(value > 0 for value in result['pieces_per_peer'].values()), result)
        self.assertTrue(all(seed.stats['payload_bytes_sent'] > 0 for seed in self.seeds))

    def test_duplicate_sources_rejected(self):
        with self.assertRaisesRegex(ValueError, 'distinct'):
            download_swarm(self.entry['torrent'], self.root / 'dup.tar.gz', name='agent.tar.gz',
                           size=self.entry['bytes'], sha256=self.digest,
                           sources=[self.seeds[0].address, self.seeds[0].address])

    def test_dead_peer_is_reassigned_to_live_peer(self):
        destination = self.root / 'out.tar.gz'
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            closed = probe.getsockname()
        result = download_swarm(self.entry['torrent'], destination, name='agent.tar.gz',
                                size=self.entry['bytes'], sha256=self.digest,
                                sources=[self.seeds[0].address, closed])
        self.assertEqual(result['sha256_verified'], True)
        self.assertEqual(len(result['failed_peers']), 1)
        self.assertEqual(destination.read_bytes(), self.asset.read_bytes())

    def test_all_peers_dead_fails_closed(self):
        destination = self.root / 'out.tar.gz'
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            closed = probe.getsockname()
        with self.assertRaisesRegex(ValueError, 'peer failure'):
            download_swarm(self.entry['torrent'], destination, name='agent.tar.gz',
                           size=self.entry['bytes'], sha256=self.digest,
                           sources=[closed, (closed[0], closed[1] + 1 if closed[1] < 65535 else closed[1] - 1)])
        self.assertFalse(destination.exists())
        self.assertFalse(destination.with_suffix(destination.suffix + '.partial').exists())

    def test_mid_transfer_peer_loss_reassigns_missing_pieces(self):
        lost = Seeder({'agent.tar.gz': (self.asset, self.entry)}, ('127.0.0.1', 0), '127.0.0.1',
                      interrupt_after_bytes=300_000)
        self.seeds.append(lost)
        destination = self.root / 'loss.tar.gz'
        result = download_swarm(self.entry['torrent'], destination, name='agent.tar.gz',
                                size=self.entry['bytes'], sha256=self.digest,
                                sources=[lost.address, self.seeds[1].address])
        self.assertTrue(result['sha256_verified'])
        self.assertEqual(len(result['failed_peers']), 1)
        self.assertGreaterEqual(result['retries'], 1)
        self.assertEqual(destination.read_bytes(), self.asset.read_bytes())
        self.assertGreater(lost.stats['payload_bytes_sent'], 0)

    def test_two_peer_losses_reassign_to_third(self):
        lost_one = Seeder({'agent.tar.gz': (self.asset, self.entry)}, ('127.0.0.1', 0), '127.0.0.1',
                          interrupt_after_bytes=300_000)
        lost_two = Seeder({'agent.tar.gz': (self.asset, self.entry)}, ('127.0.0.1', 0), '127.0.0.1',
                          interrupt_after_bytes=700_000)
        self.seeds.extend([lost_one, lost_two])
        destination = self.root / 'loss-two.tar.gz'
        result = download_swarm(self.entry['torrent'], destination, name='agent.tar.gz',
                                size=self.entry['bytes'], sha256=self.digest,
                                sources=[lost_one.address, lost_two.address, self.seeds[0].address])
        self.assertTrue(result['sha256_verified'])
        self.assertGreaterEqual(len(result['failed_peers']), 2)
        self.assertGreaterEqual(result['retries'], 2)
        self.assertEqual(destination.read_bytes(), self.asset.read_bytes())

    def test_single_peer_path_and_pin_mismatch(self):
        result = download_swarm(self.entry['torrent'], self.root / 'one.tar.gz', name='agent.tar.gz',
                                size=self.entry['bytes'], sha256=self.digest,
                                sources=[self.seeds[0].address])
        self.assertEqual(result['peer_count'], 1)
        with self.assertRaisesRegex(ValueError, 'integrity'):
            download_swarm(self.entry['torrent'], self.root / 'bad.tar.gz', name='agent.tar.gz',
                           size=self.entry['bytes'], sha256='0' * 64,
                           sources=[self.seeds[0].address])


if __name__ == '__main__':
    unittest.main()
