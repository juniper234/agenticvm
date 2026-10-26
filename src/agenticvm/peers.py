"""Run bounded, unattended encrypted host/guest and guest/guest experiments.

No model provider, host shell capability, network bridge or message relay is
installed. The small peers demonstrate the communication contract directly.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import sys
import time
from uuid import uuid4

from .peer_protocol import BIOStream, PeerError, PeerSession, PeerTLSConfig
from .qemu import QemuBackend, find_qemu
from .state import StateStore
from .transport import SocketTransport

ROOT = Path(__file__).resolve().parents[2]
MAX_CAPTURE = 4 * 1024 * 1024


def encoded(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


class Journal:
    """Durable, bounded checkpoints with a hash chain; not a signed audit log."""

    def __init__(self, directory: Path, run_id: str):
        self.directory, self.run_id = directory, run_id
        self.previous = "0" * 64
        self.count = 0
        self.file = (directory / "checkpoints.jsonl").open("x", encoding="ascii")

    def add(self, event: str, **fields):
        if set(fields).intersection({'index', 'run_id', 'event', 'at_unix_ms', 'previous', 'sha256'}):
            raise ValueError('Checkpoint fields cannot replace reserved journal metadata')
        if self.count >= 2048:
            raise ValueError("Checkpoint limit reached")
        self.count += 1
        record = {"index": self.count, "run_id": self.run_id, "event": event,
                  "at_unix_ms": int(time.time() * 1000), "previous": self.previous, **fields}
        record["sha256"] = hashlib.sha256(encoded(record)).hexdigest()
        self.previous = record["sha256"]
        self.file.write(encoded(record).decode("ascii") + "\n")
        self.file.flush()
        os.fsync(self.file.fileno())
        return record

    def close(self):
        self.file.close()


def verify_journal(path: Path) -> dict:
    if path.stat().st_size > MAX_CAPTURE:
        raise ValueError("Checkpoint file exceeds its bound")
    previous, count = "0" * 64, 0
    with path.open(encoding="ascii") as source:
        for line in source:
            value = json.loads(line)
            digest = value.pop("sha256")
            count += 1
            if value["previous"] != previous or value["index"] != count or hashlib.sha256(encoded(value)).hexdigest() != digest:
                raise ValueError("Checkpoint chain does not verify")
            previous = digest
    return {"records": count, "sha256": previous, "verified": True}


def inspect_capture(path: Path, marker: bytes | None = None) -> dict:
    """Bounded Ethernet/IPv4/TCP observations, without executing capture data."""
    if not path.is_file() or not 24 <= path.stat().st_size <= MAX_CAPTURE:
        raise ValueError("Missing or oversized packet capture")
    packets, endpoints, payloads = 0, set(), bytearray()
    with path.open("rb") as source:
        header = source.read(24)
        magic = header[:4]
        order = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">" if magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d") else None
        if order is None or struct.unpack(order + "I", header[20:24])[0] != 1:
            raise ValueError("Expected an Ethernet PCAP")
        while packet_header := source.read(16):
            if len(packet_header) != 16:
                raise ValueError("Truncated packet header")
            length = struct.unpack(order + "IIII", packet_header)[2]
            if length > 65536:
                raise ValueError("Packet exceeds its inspection bound")
            packet = source.read(length)
            if len(packet) != length:
                raise ValueError("Truncated packet")
            packets += 1
            if len(packet) < 54 or packet[12:14] != b"\x08\x00" or packet[23] != 6:
                continue
            ip_offset, ip_size = 14, (packet[14] & 15) * 4
            tcp = ip_offset + ip_size
            if ip_size < 20 or len(packet) < tcp + 20:
                raise ValueError("Invalid IPv4/TCP header")
            tcp_size = (packet[tcp + 12] >> 4) * 4
            if tcp_size < 20 or len(packet) < tcp + tcp_size:
                raise ValueError("Invalid TCP header")
            endpoints.add((socket.inet_ntoa(packet[26:30]), socket.inet_ntoa(packet[30:34]),
                           *struct.unpack("!HH", packet[tcp:tcp + 4])))
            payloads.extend(packet[tcp + tcp_size:])
    if not packets or not payloads:
        raise ValueError("Capture contains no TCP exchange")
    return {"packets": packets, "tcp_endpoints": sorted(endpoints), "tcp_payload_bytes": len(payloads),
            "tls_record_observed": b"\x16\x03\x01" in payloads or b"\x16\x03\x03" in payloads,
            "application_json_visible": b'"sender":' in payloads or b'"recipient":' in payloads,
            "marker_visible": bool(marker and marker in payloads),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "limits": "Capture observations complement authenticated TLS negotiation; absence of a string alone does not prove encryption."}


def recover_run(directory: Path) -> dict:
    """After interruption, clean owned resources without replaying messages."""
    directory = directory.resolve()
    verified = verify_journal(directory / "checkpoints.jsonl")
    if not verified["records"]:
        raise ValueError("An interrupted run must have at least one checkpoint")
    first = json.loads((directory / "checkpoints.jsonl").read_text(encoding="ascii").splitlines()[0])
    if first["event"] != "run_started":
        raise ValueError("The selected directory is not a peer run")
    run_id = first["run_id"]
    recovery = directory / ("recovery-" + uuid4().hex[:10])
    recovery.mkdir(mode=0o700)
    journal = Journal(recovery, run_id)
    errors, pairs = [], set()
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT / "src")
    journal.add("recovery_started", prior_checkpoints=verified)
    for name in ("provisioner", "serial-guest", "guest-a", "guest-b", "guest-a-serial", "guest-b-serial"):
        workspace = directory / name
        if workspace.is_symlink() or getattr(workspace, "is_junction", lambda: False)():
            errors.append({"vm": name, "reason": "redirected workspace refused"})
            continue
        try:
            state = StateStore(workspace).load(required=False)
            if not state:
                continue
            if state.get("isolated_link"):
                pairs.add(state["isolated_link"]["pair_uuid"])
            if state.get("serial_link"):
                pairs.add(state["serial_link"]["pair_uuid"])
            if state["registered"]:
                child = subprocess.run([sys.executable, "-B", "-m", "agenticvm", "--workspace", str(workspace), "stop"],
                                       cwd=ROOT, env=env, capture_output=True, timeout=20,
                                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
                result = json.loads(child.stdout)
                if child.returncode or not result.get("ok"):
                    raise RuntimeError("Owned VM could not be stopped")
                journal.add("recovered_vm", vm=name, uuid=state["uuid"], status="stopped")
        except Exception as error:
            errors.append({"vm": name, "error_class": type(error).__name__})
    if not errors:
        from .qemu import cleanup_pair_directory
        for pair in pairs:
            if not cleanup_pair_directory(pair):
                errors.append({"pair": pair, "reason": "unknown socket files retained"})
    private = directory / "private"
    if private.is_symlink() or getattr(private, "is_junction", lambda: False)():
        errors.append({"private": "redirected identity directory refused"})
    elif private.is_dir():
        for filename in ("ca.pem", "foreign-ca.pem", *[name + suffix for name in ("host", "guest-a", "guest-b", "outsider") for suffix in (".pem", ".key")]):
            path = private / filename
            if path.is_file() and not path.is_symlink():
                path.unlink()
        try:
            private.rmdir()
        except OSError:
            errors.append({"private": "unexpected identity files retained"})
    result = {"passed": not errors, "run_id": run_id, "failures": errors,
              "tasks_replayed": False, "private_identities_removed": not private.exists()}
    journal.add("recovery_completed", **{key: value for key, value in result.items() if key != "run_id"})
    journal.close()
    result["checkpoints"] = verify_journal(recovery / "checkpoints.jsonl")
    (recovery / "report.json").write_text(json.dumps(result, indent=2) + "\n", encoding="ascii")
    return {**result, "report": str(recovery / "report.json")}


class RecordedRaw:
    def __init__(self, transport, path: Path):
        self.transport = transport
        self.output = path.open("xb")
        self.count = 0

    def record(self, data: bytes):
        self.count += len(data)
        if self.count > MAX_CAPTURE:
            raise PeerError("Encrypted trace exceeds its limit")
        self.output.write(data)

    def read(self, size, timeout):
        data = self.transport.read(size, timeout)
        self.record(data)
        return data

    def write(self, data, timeout):
        self.record(data)
        self.transport.write(data, timeout)

    def close(self):
        self.transport.close()
        self.output.close()


class VM:
    def __init__(self, runner: "Runner", name: str):
        self.runner, self.name = runner, name
        self.workspace = runner.directory / name
        self.jobs = []
        self.started = False

    def cli(self, *arguments, timeout=90, expected=0):
        self.runner.control_calls += 1
        env = os.environ.copy()
        env["PYTHONPATH"] = str(ROOT / "src")
        child = subprocess.run([sys.executable, "-B", "-m", "agenticvm", "--workspace", str(self.workspace), *map(str, arguments)],
                               cwd=ROOT, env=env, stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout,
                               creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        if len(child.stdout) > 2 * 1024 * 1024:
            raise ValueError("Controller response exceeds its limit")
        envelope = json.loads(child.stdout)
        if child.returncode != expected or not envelope.get("ok"):
            raise RuntimeError(f"{self.name}: {arguments[0]} failed: " + str(envelope.get("error", envelope))[:1500])
        return envelope["result"]

    def start(self, *options):
        self.runner.machines.append(self)
        result = self.cli("start", "--profile", "agent", "--memory", self.runner.memory,
                          "--ready-timeout", "60", *options)
        self.started = True
        self.runner.journal.add("vm_ready", vm=self.name, uuid=result["uuid"], memory_mib=result["memory_mib"],
                                guest_uid=result["guest"]["uid"], profile=result["guest"]["profile"], network=result["network"])
        if result["guest"]["uid"] != 1000 or result["guest"]["profile"] != "agent":
            raise AssertionError("Expected the unprivileged headless agent profile")
        return result

    def run(self, *argv):
        result = self.cli("exec", "--timeout-ms", "30000", "--", *argv)
        if result["exit_code"] != 0:
            raise RuntimeError(self.name + ": guest command failed: " + result.get("stderr", "")[-1000:])
        return result["stdout"]

    def upload(self, path: Path, guest_path: str):
        self.cli("put", path, guest_path)

    def download(self, guest_path: str, path: Path):
        self.cli("get", guest_path, path)

    def install(self, identity: str, peer: str):
        self.run("/bin/mkdir", "-p", "/workspace/peer")
        for source in (ROOT / "guest/peer_agent.py", ROOT / "src/agenticvm/peer_protocol.py"):
            self.upload(source, "peer/" + source.name)
        for name, destination in ((identity + ".pem", "identity.pem"), (identity + ".key", "key.pem"), ("ca.pem", "ca.pem")):
            self.upload(self.runner.pki / name, "peer/" + destination)
        self.run("/bin/chmod", "600", "/workspace/peer/key.pem")
        self.runner.journal.add("agent_installed", vm=self.name, identity=identity, peer=peer,
                                cert_sha256=self.runner.identities[identity]["sha256"],
                                source_sha256={source.name: hashlib.sha256(source.read_bytes()).hexdigest() for source in
                                               (ROOT / "guest/peer_agent.py", ROOT / "src/agenticvm/peer_protocol.py")})

    def agent(self, identity: str, peer: str, *options):
        argv = ["/usr/bin/python3", "-I", "/workspace/peer/peer_agent.py", "--identity", identity,
                "--peer-identity", peer, "--run-id", self.runner.run_id, "--peer-sha256",
                self.runner.identities[peer]["sha256"], "--deadline", "90", *options]
        result = self.cli("exec", "--async", "--timeout-ms", "0", "--", *argv)
        self.jobs.append(result["job_id"])
        return result["job_id"]

    def wait(self, job: str, timeout=30, expected=0):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            result = self.cli("poll", job, "--wait-ms", "500")
            if result["state"] == "exited":
                if result["exit_code"] != expected:
                    raise RuntimeError(self.name + ": agent failed: " + result.get("stderr", "")[-1000:])
                self.cli("forget", job)
                self.jobs.remove(job)
                return result
        raise TimeoutError(self.name + ": agent did not finish")

    def collect(self):
        folder = self.runner.directory / "evidence" / self.name
        folder.mkdir(parents=True)
        for filename in ("evidence.jsonl", "summary.json"):
            self.download("peer/" + filename, folder / filename)
        summary = json.loads((folder / "summary.json").read_text())
        if summary.get("passed") is not True:
            raise AssertionError(self.name + ": peer summary did not pass")
        records = [json.loads(line) for line in (folder / "evidence.jsonl").read_text().splitlines()]
        return summary, records

    def stop(self):
        state = StateStore(self.workspace).load(required=False)
        if state and state["registered"]:
            result = self.cli("stop")
            self.runner.journal.add("vm_stopped", vm=self.name, uuid=state["uuid"], cleanup=result.get("socket_cleanup"))
        self.started = False


class Runner:
    def __init__(self, directory: Path, run_id: str, memory: int, rounds: int):
        self.directory, self.run_id, self.memory, self.rounds = directory, run_id, memory, rounds
        self.journal = Journal(directory, run_id)
        self.machines = []
        self.pki = directory / "private"
        self.pki.mkdir(mode=0o700)
        self.identities = {}
        self.pair_id = None
        self.results = {}
        self.control_calls = 0

    def provision(self):
        # A separate trusted provisioner is destroyed BEFORE either endpoint
        # starts. No endpoint receives another endpoint's private key.
        provisioner = VM(self, "provisioner")
        provisioner.start()
        provisioner.run("/bin/mkdir", "-p", "/workspace/peer")
        provisioner.upload(ROOT / "guest/peer_pki.py", "peer/peer_pki.py")
        public = json.loads(provisioner.run("/usr/bin/python3", "-I", "/workspace/peer/peer_pki.py", "--output",
                                           "/workspace/peer/pki", "--run-id", self.run_id, "--identities",
                                           "host", "guest-a", "guest-b", "outsider"))
        self.identities = public["identities"]
        for filename in ["ca.pem", *[name + suffix for name in self.identities for suffix in (".pem", ".key")]]:
            provisioner.download("peer/pki/" + filename, self.pki / filename)
        # An unrelated CA provides a real wrong-trust negative test.
        provisioner.run("/usr/bin/python3", "-I", "/workspace/peer/peer_pki.py", "--output", "/workspace/peer/foreign",
                        "--run-id", str(uuid4()), "--identities", "foreign")
        provisioner.download("peer/foreign/ca.pem", self.pki / "foreign-ca.pem")
        (self.directory / "identities.json").write_text(json.dumps(public, indent=2) + "\n", encoding="ascii")
        provisioner.stop()
        self.journal.add("pki_ready", identities=public, provisioning_vm_stopped=True,
                         global_trust_store_changed=False)

    def configuration(self, identity: str, peer: str, *, pin: str | None = None, ca="ca.pem"):
        return PeerTLSConfig(str(self.pki / (identity + ".pem")), str(self.pki / (identity + ".key")),
                             str(self.pki / ca), pin or self.identities[peer]["sha256"], peer)

    def host_guest(self):
        vm = VM(self, "serial-guest")
        vm.start("--peer-channel")
        vm.install("guest-a", "host")
        job = vm.agent("guest-a", "host", "--transport", "serial", "--role", "server", "--connections", "2",
                       "--max-requests", str(self.rounds * 3 + 2))
        self.journal.add("host_guest_ready", vm=vm.name, transport="TLS1.3 over virtio-serial", host_tcp_listener=False)
        store = StateStore(vm.workspace)
        state = store.load()
        backend = QemuBackend(store, Path(state["executable"]))

        def connect(config, filename):
            # Prove exact process ownership immediately before opening its port.
            with backend._process(state) as process:
                if not process.alive():
                    raise RuntimeError("The owned VM exited")
                raw = RecordedRaw(SocketTransport(state["peer_socket"], 5), self.directory / filename)
            return BIOStream(raw, config, server_side=False, timeout=8)

        rejected = []
        for label, configuration in (("wrong_pin", self.configuration("host", "guest-a", pin="0" * 64)),
                                      ("wrong_ca", self.configuration("host", "guest-a", ca="foreign-ca.pem")),
                                      ("unexpected_client", self.configuration("outsider", "guest-a"))):
            stream = None
            try:
                stream = connect(configuration, label + ".tls")
                PeerSession(stream, self.run_id, "outsider" if label == "unexpected_client" else "host", "guest-a").request("hello", timeout=5)
            except (OSError, ValueError, TimeoutError, RuntimeError) as error:
                if label == "wrong_pin" and not (isinstance(error, PeerError) and error.code == "pin_mismatch"):
                    raise AssertionError("Wrong-pin check failed for a reason other than the expected pin rejection") from error
                if label == "wrong_ca" and not isinstance(error, ssl.SSLCertVerificationError):
                    raise AssertionError("Wrong-CA check did not produce a certificate verification failure") from error
                rejected.append(label)
                self.journal.add("identity_rejected", topology="host_guest", case=label, error_class=type(error).__name__)
            else:
                raise AssertionError("An invalid peer was accepted: " + label)
            finally:
                if stream:
                    stream.close()
            time.sleep(0.3)
        marker = "private-serial-" + uuid4().hex
        accepted = []
        for conversation in range(2):
            stream = connect(self.configuration("host", "guest-a"), f"host-guest-{conversation}.tls")
            try:
                session = PeerSession(stream, self.run_id, "host", "guest-a", lambda event: self.journal.add("host_peer", detail=event))
                session.request("hello")
                for index in range(self.rounds):
                    text = f"{marker} {index} caf\u00e9 \u4e2d\u6587 \U0001f680 $(id)"
                    session.request("ping", nonce=str(uuid4()))
                    assert session.request("echo", text=text)["text"] == text
                    assert session.request("sha256", text=text)["sha256"] == hashlib.sha256(text.encode()).hexdigest()
                session.request("close")
                accepted.append(stream.info)
            finally:
                stream.close()
            time.sleep(0.3)
        vm.wait(job)
        summary, records = vm.collect()
        if not any(event.get("event") == "rejected" and event.get("error_code") == "pin_mismatch" for event in records):
            raise AssertionError("The guest did not explicitly reject the unexpected client certificate pin")
        for index in range(2):
            trace = (self.directory / f"host-guest-{index}.tls").read_bytes()
            if marker.encode() in trace or b'"sender":' in trace:
                raise AssertionError("Application plaintext appeared in the wire trace")
        vm.stop()
        self.results["host_guest"] = {"passed": True, "conversations": 2, "requests_per_conversation": self.rounds * 3 + 2,
                                      "rejected_identities": rejected, "tls": accepted, "summary": summary,
                                      "unexpected_client_rejection_verified_by_server": True,
                                      "guest_checkpoint_count": len(records), "plaintext_marker_visible": False}
        self.journal.add("host_guest_passed", **self.results["host_guest"])

    def guest_guest(self, *, serial=False):
        from .qemu import prepare_pair_directory
        from .state import qemu_socket_directory
        self.pair_id = str(uuid4())
        prepare_pair_directory(self.pair_id)
        left, right = VM(self, "guest-a-serial" if serial else "guest-a"), VM(self, "guest-b-serial" if serial else "guest-b")
        medium = "serial" if serial else "ethernet"
        transport = "serial" if serial else "tcp"
        topology = "guest_guest_serial" if serial else "guest_guest"
        left.start("--pair", self.pair_id, "--peer-role", "listen", "--peer-link", medium, *([] if serial else ["--peer-capture"]))
        right.start("--pair", self.pair_id, "--peer-role", "connect", "--peer-link", medium)
        left.install("guest-a", "guest-b")
        right.install("guest-b", "guest-a")
        snapshots = {}
        network_probe = ("import socket,json,pathlib; out={'interfaces':sorted(p.name for p in pathlib.Path('/sys/class/net').iterdir()),'routes':pathlib.Path('/proc/net/route').read_text(),"
                         "'dns':pathlib.Path('/etc/resolv.conf').read_text(),'unreachable':{}}; "
                         "exec(\"for host in ['10.0.2.2','1.1.1.1']:\\n s=socket.socket(); s.settimeout(.3)\\n "
                         "try: s.connect((host,443)); out['unreachable'][host]=False\\n "
                         "except OSError as e: out['unreachable'][host]=e.errno in (101,113)\\n "
                         "finally: s.close()\"); print(json.dumps(out))")
        for vm in (left, right):
            snapshot = json.loads(vm.run("/usr/bin/python3", "-I", "-c", network_probe))
            if not all(snapshot["unreachable"].values()) or any(line.split()[1] == "00000000" for line in snapshot["routes"].splitlines()[1:]):
                raise AssertionError("The private guest network has an unexpected route")
            if serial and (snapshot["interfaces"] != ["lo"] or len(snapshot["routes"].splitlines()) != 1 or snapshot["dns"].strip()):
                raise AssertionError("A serial-only guest unexpectedly has a NIC, route or DNS configuration")
            snapshots[vm.name] = snapshot
        server = right.agent("guest-b", "guest-a", "--transport", transport, "--role", "server", "--connections", "1",
                             "--max-requests", str(self.rounds * 3 + 2))
        negative = left.agent("guest-a", "guest-b", "--transport", transport, "--role", "client",
                              "--peer-sha256", "0" * 64,
                              "--evidence", "/workspace/peer/rejected-pin.jsonl",
                              "--summary", "/workspace/peer/rejected-pin-summary.json")
        left.wait(negative, expected=1)
        rejected_path = self.directory / ("guest-guest-serial-rejected-pin.jsonl" if serial else "guest-guest-rejected-pin.jsonl")
        left.download("peer/rejected-pin.jsonl", rejected_path)
        rejected_events = [json.loads(line) for line in rejected_path.read_text().splitlines()]
        if not any(event.get("event") == "rejected" and event.get("error_code") == "pin_mismatch" for event in rejected_events):
            raise AssertionError("Guest wrong-pin test did not record an explicit authentication rejection")
        self.journal.add("identity_rejected", topology=topology, case="wrong_pin", error_code="pin_mismatch")
        time.sleep(0.3)
        client = left.agent("guest-a", "guest-b", "--transport", transport, "--role", "client",
                            "--rounds", self.rounds, "--start-delay", "2", "--interval", "0.25")
        calls_before = self.control_calls
        begin = self.journal.add("control_detached", control_calls_before=calls_before,
                                 message_relay=False, host_network_interface=False)
        # This interval deliberately performs NO guest RPC, filesystem transfer,
        # host relay or acknowledgement. Only the guests drive their exchange.
        quiet_seconds = max(7, 3 + self.rounds * 0.3)
        time.sleep(quiet_seconds)
        calls_during = self.control_calls - calls_before
        end = self.journal.add("control_resumed", quiet_seconds=quiet_seconds, control_requests_during_interval=calls_during)
        if calls_during:
            raise AssertionError("An administrative call occurred during the detached interval")
        left.wait(client)
        right.wait(server)
        left_summary, left_records = left.collect()
        right_summary, right_records = right.collect()
        rounds = [event for event in left_records if event["event"] == "round_completed"]
        if len(rounds) != self.rounds or not all(begin["at_unix_ms"] <= event["at_unix_ms"] <= end["at_unix_ms"] for event in rounds):
            raise AssertionError("Guest exchanges were not completed during the detached interval")
        sent = {event["message_id"] for event in left_records if event["event"] == "sent"}
        received = {event["message_id"] for event in right_records if event["event"] == "received"}
        acknowledged = {event["message_id"] for event in left_records if event["event"] == "acknowledged"}
        sent_hashes = {event["message_id"]: event["body_sha256"] for event in left_records if event["event"] == "sent"}
        received_hashes = {event["message_id"]: event["body_sha256"] for event in right_records if event["event"] == "received"}
        if sent != received or sent != acknowledged or sent_hashes != received_hashes or len(sent) != self.rounds * 3 + 2:
            raise AssertionError("Guest message acknowledgements do not match")
        state = StateStore(left.workspace).load()
        capture = Path(state["run_dir"]) / "peer.pcap"
        left.stop()
        right.stop()
        observation = None if serial else inspect_capture(capture)
        if not serial and (not observation["tls_record_observed"] or observation["application_json_visible"] or any({row[0], row[1]} != {"192.0.2.1", "192.0.2.2"} for row in observation["tcp_endpoints"])):
            raise AssertionError("Unexpected private network capture")
        self.results[topology] = {"passed": True, "medium": medium, "rounds": self.rounds, "acknowledged_requests": len(sent),
                                       "rejected_identities": ["wrong_pin"],
                                       "control_detached_ms": end["at_unix_ms"] - begin["at_unix_ms"],
                                       "control_requests_during_interval": calls_during,
                                       "network": snapshots, "capture": observation,
                                       "client": left_summary, "server": right_summary,
                                       "host_application_relay": False}
        self.journal.add(topology + "_passed", **self.results[topology])
        from .qemu import cleanup_pair_directory
        if not cleanup_pair_directory(self.pair_id):
            raise RuntimeError("Pair socket cleanup did not finish")
        self.pair_id = None

    def diagnose(self):
        """Collect public failure evidence while ephemeral guests still exist."""
        for vm in self.machines:
            if not vm.started:
                continue
            folder = self.directory / "failure-evidence" / vm.name
            folder.mkdir(parents=True, exist_ok=True)
            try:
                status = vm.cli("status")
                (folder / "status.json").write_text(json.dumps(status, indent=2) + "\n", encoding="ascii")
                for job in vm.jobs:
                    snapshot = vm.cli("poll", job)
                    (folder / ("job-" + job + ".json")).write_text(json.dumps(snapshot, indent=2) + "\n", encoding="ascii")
                for filename in ("evidence.jsonl", "summary.json"):
                    try:
                        vm.download("peer/" + filename, folder / filename)
                    except Exception:
                        pass
            except Exception as error:
                self.journal.add("diagnostic_unavailable", vm=vm.name, error_class=type(error).__name__)

    def cleanup(self):
        errors = []
        for vm in reversed(self.machines):
            try:
                vm.stop()
            except Exception as error:
                errors.append({"vm": vm.name, "error_class": type(error).__name__})
        if self.pair_id and not errors:
            from .qemu import cleanup_pair_directory
            if not cleanup_pair_directory(self.pair_id):
                errors.append({"pair": self.pair_id, "error_class": "cleanup_failed"})
        # Exact, newly generated identity files only; never remove user paths.
        for filename in ["ca.pem", "foreign-ca.pem", *[name + suffix for name in self.identities for suffix in (".pem", ".key")]]:
            path = self.pki / filename
            if path.is_file() and not path.is_symlink():
                path.unlink()
        try:
            self.pki.rmdir()
        except OSError:
            errors.append({"private_files": "unexpected files retained"})
        self.journal.add("cleanup", passed=not errors, failures=errors, private_identities_removed=not self.pki.exists())
        return errors


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("all", "both", "host-guest", "guest-guest", "guest-guest-serial"), default="both")
    parser.add_argument("--rounds", type=int, default=8)
    parser.add_argument("--memory", type=int, choices=(256, 384, 512), default=256)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--recover", type=Path, help="Clean a checkpointed interrupted run; never replay its messages")
    args = parser.parse_args(argv)
    if args.recover:
        result = recover_run(args.recover)
        print(json.dumps(result, ensure_ascii=True))
        return 0 if result["passed"] else 1
    if not 1 <= args.rounds <= 32:
        parser.error("Use one to 32 rounds")
    run_id = str(uuid4())
    directory = (args.output or ROOT / "runtime/peer-runs" / run_id).absolute()
    if directory.exists() or directory.is_symlink():
        parser.error("Choose a new output directory; existing runs are preserved")
    directory.mkdir(parents=True, mode=0o700)
    runner = Runner(directory, run_id, args.memory, args.rounds)
    started = time.monotonic()
    error = None
    try:
        runner.journal.add("run_started", mode=args.mode, rounds=args.rounds, memory_mib=args.memory)
        runner.provision()
        if args.mode in ("all", "both", "host-guest"):
            runner.host_guest()
        if args.mode in ("all", "both", "guest-guest"):
            runner.guest_guest()
        if args.mode in ("all", "guest-guest-serial"):
            runner.guest_guest(serial=True)
    except (Exception, KeyboardInterrupt) as failure:
        error = {"class": type(failure).__name__, "message": str(failure)[:1500]}
        runner.journal.add("run_failed", error=error)
        runner.diagnose()
    finally:
        cleanup_errors = runner.cleanup()
        passed = error is None and not cleanup_errors
        runner.journal.add("run_completed", passed=passed, elapsed_seconds=round(time.monotonic() - started, 3))
        runner.journal.close()
    report = {"schema": "agenticvm.peer-run.v1", "run_id": run_id, "passed": passed, "mode": args.mode,
              "memory_mib_per_guest": args.memory, "rounds": args.rounds, "results": runner.results,
              "failure": error, "cleanup_failures": cleanup_errors,
              "checkpoints": verify_journal(directory / "checkpoints.jsonl"),
              "physical_4gb_host_tested": False,
              "limits": "The hypervisor and provisioning host are trusted. Peers have no host network access; this does not hide memory or keys from a malicious hypervisor. Deterministic peers prove transport, not model inference."}
    (directory / "report.json").write_text(json.dumps(report, indent=2, ensure_ascii=True) + "\n", encoding="ascii")
    print(json.dumps({"passed": passed, "report": str(directory / "report.json"), "failure": error}, ensure_ascii=True))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
