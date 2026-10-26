"""Hardware tier and broker routing tests; no model assets or execution."""
import unittest

from agenticvm.garden_broker import Broker, Hardware, ModelProfile, select_tier


def profiles():
    return [
        ModelProfile('T0', 'LFM2.5-350M-Q4_K_M', 'a'*64, 1024, minimum_memory_mib=512, minimum_cpus=1),
        ModelProfile('T1', 'Qwen2.5-1.5B-Instruct', 'b'*64, 8192, minimum_memory_mib=8192),
        ModelProfile('T2', 'Mistral-7B-Instruct', 'c'*64, 16384, minimum_memory_mib=16384),
        ModelProfile('T3', 'Llama-3.1-70B-Instruct', 'd'*64, 32768, minimum_memory_mib=32768),
    ]


class BrokerTests(unittest.TestCase):
    def test_tier_boundaries(self):
        self.assertEqual(select_tier(Hardware(512, 1), profiles()).tier, 'T0')
        self.assertEqual(select_tier(Hardware(8192, 2), profiles()).tier, 'T1')
        self.assertEqual(select_tier(Hardware(16384, 4), profiles()).tier, 'T2')
        self.assertEqual(select_tier(Hardware(65536, 16), profiles()).tier, 'T3')

    def test_below_minimum_fails(self):
        for hardware in (Hardware(511, 8), Hardware(512, 0)):
            with self.subTest(hardware=hardware), self.assertRaisesRegex(ValueError, 'fits'):
                select_tier(hardware, profiles())

    def test_route_is_within_hardware_tier(self):
        result = Broker(profiles()).route(Hardware(8192, 2))
        self.assertEqual(result['tier'], 'T1')
        self.assertFalse(result['fallback'])
        self.assertFalse(result['executed'])

    def test_outage_falls_back_lower_only(self):
        broker = Broker(profiles())
        broker.set_outage('T1', True)
        result = broker.route(Hardware(8192, 2))
        self.assertEqual(result['tier'], 'T0')
        self.assertTrue(result['fallback'])
        broker.set_outage('T0', True)
        with self.assertRaisesRegex(ValueError, 'lower'):
            broker.route(Hardware(8192, 2))

    def test_no_fallback_higher(self):
        broker = Broker(profiles())
        broker.set_outage('T3', True)
        result = broker.route(Hardware(65536, 16))
        self.assertEqual(result['tier'], 'T2')
        self.assertLess(result['context'], 32768)

    def test_duplicate_tier_and_bad_profile_rejected(self):
        with self.assertRaises(ValueError):
            Broker(profiles() + [ModelProfile('T0', 'x', 'e'*64, 2048)])
        with self.assertRaises(ValueError):
            ModelProfile('T9', 'x', 'e'*64, 2048)
        with self.assertRaises(ValueError):
            ModelProfile('T0', 'x', 'not-a-hash', 2048)

    def test_fallback_disabled_rejects_outage(self):
        broker = Broker(profiles())
        broker.set_outage('T2', True)
        with self.assertRaises(ValueError):
            broker.route(Hardware(16384, 4), allow_fallback=False)
