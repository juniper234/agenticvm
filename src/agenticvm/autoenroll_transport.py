"""Bounded invite transport adapters for auto-enrollment.

Transport is delivery-only. A sub-agent courier receives a mother-signed
delivery grant, cannot mint or change an invite, and has no admission method.
Native networking is deliberately absent from this host-only module.
"""
from __future__ import annotations

import copy
import time
from abc import ABC, abstractmethod
from uuid import UUID

from .autoenroll_inventory import digest_json, verify_delivery_grant


def _uuid(value, label):
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a canonical UUID")
    try:
        parsed = UUID(value)
    except (ValueError, TypeError) as error:
        raise ValueError(f"{label} must be a canonical UUID") from error
    if str(parsed) != value:
        raise ValueError(f"{label} must be a canonical UUID")
    return value


def _target_binding(invite, target):
    if not isinstance(target, dict) or target.get("uuid") != invite["target_uuid"] or target.get("mac") != invite["target_mac"]:
        raise ValueError("Transport target binding mismatch")


def _delivery_result(result, invite):
    if not isinstance(result, dict) or result.get("delivered") is not True:
        raise ValueError("Invite delivery did not complete")
    if result.get("invite_sha256") != digest_json(invite):
        raise ValueError("Transport altered the invite")
    return result


class InviteTransport(ABC):
    @abstractmethod
    def deliver(self, invite, *, target, grant=None):
        """Deliver one mother-signed invite to a registered target."""

    @abstractmethod
    def collect(self, *, request_id):
        """Collect the target receipt for one request; never admit it."""


class MotherDirectTransport(InviteTransport):
    """Mode B mother-direct delivery. A delivery grant is neither needed nor accepted."""

    def __init__(self, deliver, collect):
        if not callable(deliver) or not callable(collect):
            raise ValueError("Mother-direct transport callbacks are required")
        self._deliver = deliver
        self._collect = collect

    def deliver(self, invite, *, target, grant=None):
        if grant is not None:
            raise ValueError("Mother-direct delivery does not use a courier grant")
        _target_binding(invite, target)
        result = self._deliver(copy.deepcopy(invite), copy.deepcopy(target))
        return _delivery_result(result, invite)

    def collect(self, *, request_id):
        request_id = _uuid(request_id, "request UUID")
        result = self._collect(request_id)
        if not isinstance(result, dict) or result.get("request_id") != request_id:
            raise ValueError("Receipt collection did not match the request")
        return result


class SubAgentCourierTransport(InviteTransport):
    """Courier delivery constrained by a mother-signed delivery grant."""

    def __init__(self, *, sub_agent, policy, deliver, collect, now=None):
        if not isinstance(sub_agent, str) or not sub_agent or len(sub_agent) > 64:
            raise ValueError("A bounded sub-agent identity is required")
        if not callable(deliver) or not callable(collect):
            raise ValueError("Courier transport callbacks are required")
        self.sub_agent = sub_agent
        self.policy = policy
        self._deliver = deliver
        self._collect = collect
        self._clock = now if callable(now) else (lambda: int(time.time()) if now is None else int(now))

    def deliver(self, invite, *, target, grant):
        if not isinstance(grant, dict):
            raise ValueError("A courier requires a mother-signed delivery grant")
        verify_delivery_grant(grant, invite, self.policy, now=self._clock())
        if grant["sub_agent"] != self.sub_agent:
            raise ValueError("Delivery grant belongs to another sub-agent")
        _target_binding(invite, target)
        result = self._deliver(copy.deepcopy(invite), copy.deepcopy(target), copy.deepcopy(grant))
        return _delivery_result(result, invite)

    def collect(self, *, request_id):
        request_id = _uuid(request_id, "request UUID")
        result = self._collect(request_id)
        if not isinstance(result, dict) or result.get("request_id") != request_id:
            raise ValueError("Receipt collection did not match the request")
        return result
