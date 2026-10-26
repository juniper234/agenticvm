"""Create disposable test identities using the guest's packaged OpenSSL.

The CA private key never leaves this process's temporary guest directory.
This helper does not read an existing identity or modify any trust store.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import ssl
import subprocess
import tempfile
from uuid import UUID


def issue(output: Path, run_id: str, identities: list[str]) -> dict:
    if str(UUID(run_id)) != run_id or not identities or len(identities) > 8:
        raise ValueError("Use a canonical run UUID and one to eight identities")
    if len(set(identities)) != len(identities) or any(not re.fullmatch(r"[a-z][a-z0-9-]{0,31}", name) for name in identities):
        raise ValueError("Identity names must be unique short lowercase names")
    if output.exists() or output.is_symlink() or not output.parent.is_dir():
        raise ValueError("Choose a fresh directory beneath an existing parent")
    os.umask(0o077)
    output.mkdir(mode=0o700)

    def openssl(*arguments: str):
        child = subprocess.run(["/usr/bin/openssl", *arguments], stdin=subprocess.DEVNULL,
                               capture_output=True, timeout=15, check=False)
        if child.returncode:
            # OpenSSL commands contain paths and public identity labels only.
            raise RuntimeError("Certificate generation failed: " + child.stderr.decode("utf-8", "replace")[-1000:])

    with tempfile.TemporaryDirectory(prefix=".authority-", dir=output) as temporary:
        private = Path(temporary)
        authority, authority_key = output / "ca.pem", private / "ca.key"
        openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-noenc",
                "-sha256", "-days", "2", "-subj", "/CN=AgenticVM disposable " + run_id,
                "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                "-keyout", str(authority_key), "-out", str(authority))
        result = {"run_id": run_id, "algorithm": "ECDSA P-256", "leaf_validity_days": 1,
                  "ca_private_key_exported": False, "identities": {}}
        for name in identities:
            key, request, certificate = output / (name + ".key"), private / (name + ".csr"), output / (name + ".pem")
            extensions = private / (name + ".conf")
            extensions.write_text("basicConstraints=critical,CA:FALSE\n"
                                  "keyUsage=critical,digitalSignature\n"
                                  "extendedKeyUsage=serverAuth,clientAuth\n"
                                  "subjectAltName=URI:urn:agenticvm:peer:" + name + "\n", encoding="ascii")
            openssl("req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-noenc",
                    "-subj", "/CN=" + name, "-keyout", str(key), "-out", str(request))
            openssl("x509", "-req", "-in", str(request), "-CA", str(authority), "-CAkey", str(authority_key),
                    "-set_serial", str(int.from_bytes(os.urandom(16), "big") or 1), "-sha256", "-days", "1",
                    "-extfile", str(extensions), "-out", str(certificate))
            der = ssl.PEM_cert_to_DER_cert(certificate.read_text(encoding="ascii"))
            result["identities"][name] = {"cert": certificate.name, "key": key.name,
                                          "sha256": hashlib.sha256(der).hexdigest(),
                                          "uri": "urn:agenticvm:peer:" + name}
    # TemporaryDirectory has removed the issuer private key before success.
    result["ca_private_key_removed"] = True
    (output / "public-manifest.json").write_text(json.dumps(result, indent=2) + "\n", encoding="ascii")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--identities", nargs="+", required=True)
    args = parser.parse_args()
    print(json.dumps(issue(args.output, args.run_id, args.identities)))


if __name__ == "__main__":
    main()
