"""Upstream pyghmi BMC with explicit unsupported-suite negotiation.

pyghmi 1.6.19's BMC supports cipher suite 3 but silently accepts a client's
SHA256 proposal. Reply with the protocol error so the stock client negotiates
the supported suite. Cryptographic/session processing stays upstream.
"""
from __future__ import annotations
import sys
from .lan_lab import ROOT

sys.path.insert(0, str(ROOT / 'tools/enrollment-management'))
from pyghmi.ipmi.bmc import Bmc
from pyghmi.ipmi.private.serversession import ServerSession


class NegotiatedSession(ServerSession):
    def create_open_session_response(self, request):
        if len(request) < 32:
            raise ValueError('Truncated IPMI open-session proposal')
        if request[12] != 1 or request[20] != 1 or request[28] != 1:
            self.clientsessionid = request[4:8]
            # RMCP+ 0x11: no matching integrity payload. A new SHA1/AES
            # proposal can be negotiated normally; no key check is skipped.
            return bytearray([request[0], 0x11, 4, 0]) + self.clientsessionid
        return super().create_open_session_response(request)


class LoopbackBMC(Bmc):
    def __init__(self, authdata, *, bmcuuid):
        super().__init__(authdata, port=0, bmcuuid=bmcuuid, address='::1')
        # Upstream registers server sessions by BMC port, so an ephemeral
        # bind must publish the allocated port before the first session.
        self.port = self.serversocket.getsockname()[1]
    def sessionless_data(self, data, sockaddr):
        if sockaddr[0] != '::1':
            return
        if len(data) >= 32 and data[0] == 6 and data[2:4] == b'\xff\x07' and data[4] == 6 and data[5] == 16:
            NegotiatedSession(self.authdata, self.kg, sockaddr, self.serversocket, data[16:], self.uuid, bmc=self)
            return
        return super().sessionless_data(data, sockaddr)
