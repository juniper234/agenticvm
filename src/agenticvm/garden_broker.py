"""Hardware-tiered model broker contract; no model execution or download."""
from __future__ import annotations

from dataclasses import dataclass
import re

TIER_ORDER = ('T0', 'T1', 'T2', 'T3')
SHA = re.compile(r'^[0-9a-f]{64}$')
NAME = re.compile(r'^[A-Za-z0-9._-]{1,96}$')


@dataclass(frozen=True)
class Hardware:
    memory_mib: int
    cpus: int
    gpu_vram_mib: int = 0

    def __post_init__(self):
        for name in ('memory_mib', 'cpus', 'gpu_vram_mib'):
            if type(getattr(self, name)) is not int or getattr(self, name) < 0:
                raise ValueError('Hardware fields must be nonnegative integers')


@dataclass(frozen=True)
class ModelProfile:
    tier: str
    name: str
    sha256: str
    context: int
    uncensored: bool = True
    minimum_memory_mib: int = 512
    minimum_cpus: int = 1

    def __post_init__(self):
        if self.tier not in TIER_ORDER:
            raise ValueError('Unknown model tier')
        if not isinstance(self.name, str) or not NAME.fullmatch(self.name):
            raise ValueError('Invalid model name')
        if not isinstance(self.sha256, str) or not SHA.fullmatch(self.sha256):
            raise ValueError('Invalid model SHA-256')
        if type(self.context) is not int or not 512 <= self.context <= 1_000_000:
            raise ValueError('Invalid model context')
        if type(self.uncensored) is not bool:
            raise ValueError('uncensored must be boolean')
        if type(self.minimum_memory_mib) is not int or not 512 <= self.minimum_memory_mib <= 1_000_000:
            raise ValueError('Invalid model memory floor')
        if type(self.minimum_cpus) is not int or not 1 <= self.minimum_cpus <= 256:
            raise ValueError('Invalid model CPU floor')


def fits(profile: ModelProfile, hardware: Hardware) -> bool:
    return (profile.minimum_memory_mib <= hardware.memory_mib
            and profile.minimum_cpus <= hardware.cpus)


def select_tier(hardware: Hardware, profiles) -> ModelProfile:
    allowed = [p for p in profiles if fits(p, hardware)]
    if not allowed:
        raise ValueError('No model tier fits this hardware')
    best = max(allowed, key=lambda p: TIER_ORDER.index(p.tier))
    return best


class Broker:
    """Select a model profile without exceeding the host's hardware tier."""

    def __init__(self, profiles):
        profiles = tuple(profiles)
        if not profiles:
            raise ValueError('At least one model profile is required')
        tiers = [p.tier for p in profiles]
        if len(set(tiers)) != len(tiers):
            raise ValueError('Duplicate model tier')
        self.profiles = {p.tier: p for p in profiles}
        self.outage = set()

    def set_outage(self, tier, unavailable):
        if tier not in self.profiles:
            raise ValueError('Unknown model tier')
        if unavailable:
            self.outage.add(tier)
        else:
            self.outage.discard(tier)

    def route(self, hardware, *, allow_fallback=True):
        selected = select_tier(hardware, self.profiles.values())
        if selected.tier not in self.outage:
            return self._result(selected, fallback=False)
        if not allow_fallback:
            raise ValueError('Selected model tier is unavailable')
        lower = [p for p in self.profiles.values()
                 if TIER_ORDER.index(p.tier) < TIER_ORDER.index(selected.tier) and p.tier not in self.outage
                 and fits(p, hardware)]
        if not lower:
            raise ValueError('No available lower model tier')
        return self._result(max(lower, key=lambda p: TIER_ORDER.index(p.tier)), fallback=True)

    @staticmethod
    def _result(profile, *, fallback):
        return {'tier': profile.tier, 'name': profile.name, 'sha256': profile.sha256,
                'context': profile.context, 'uncensored': profile.uncensored,
                'fallback': fallback, 'executed': False}
