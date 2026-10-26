# Reproduce the host tests

The full host suite exercises actual loopback sockets, independent libtorrent interoperability, signed/sealed messages, PE hashing, authenticated IPMI negotiation and VM-control ownership denials. It does not start native VMs. Missing dependencies and build assets are preparation failures, not reasons to weaken those assertions.

## Pinned Windows environment

Use a bootstrap Python 3.11 or newer. From the checkout:

```powershell
python scripts/prepare-test-environment.py --download --asset-cache "C:\path\to\prepared-AgenticVM"
.\tools\test-environment\python.exe -I -B scripts/run-host-tests.py --temp-root "C:\short\writable\folder"
```

`--download` explicitly permits HTTPS retrieval of the pinned CPython 3.13.16 embedded runtime and wheels. Every archive is size/SHA256 checked before extraction. The separate test interpreter includes its dependencies even in `-I` subprocesses; it does not modify the production interpreter or global settings. Repeat preparation reuses only matching files. Existing changed files and redirected paths are refused.

Without `--download`, dependencies must already exist in the verified local cache. The cache, interpreter, wheels, images and test receipts are ignored by Git.

## Prepared build checks

The full suite retains its real prepared-image and firmware assertions. `tools/test-assets-lock.json` lists the baseline artifacts and hashes. `--asset-cache` reads an existing owned checkout/build cache and imports only those pinned artifacts; matching tracked source inputs are verified rather than replaced.

The corresponding builders are `scripts/build-linux-pxe.py`, `scripts/prepare-realism-tools.py` and `scripts/prepare-uki-stub.py`. Their dependency/media preparation is separate from running tests. A newly rebuilt baseline with different package/image hashes requires an independently reviewed lock update; the import command never blesses mismatching files. It does not import account data, Windows disks, session directories or arbitrary files.

Windows unattended-selector unit tests use their own bounded, hash-pinned fixture metadata. They do not need a prepared Windows account/image or credentials. Separate tamper and wrong-image tests retain the refusal checks.

## Standard virtual environment

If using a regular local Python environment instead of the portable interpreter:

```powershell
python -m pip install -e .
python -m pip install -r requirements-test.txt
python scripts/run-host-tests.py --temp-root "C:\short\writable\folder"
```

The same prepared assets are still required. The pinned dependency set targets the tested Windows x86-64 / Python 3.13 baseline; another platform must supply compatible upstream dependencies and its own evidence.

## Test isolation and ordering

Choose an existing writable temporary root short enough for the OS's 107-byte private socket pathname limit, including the temporary folder and session UUID. The runner checks this before starting tests and scopes/restores its temporary environment. It never replaces private sockets with a network listener to evade the limit.

```powershell
.\tools\test-environment\python.exe -I -B scripts/run-host-tests.py --temp-root "C:\short\writable\folder" --order shuffle --seed 26026
```

Normal, reverse and deterministic shuffled order are supported. Each run records counts, skips, order, source hashes and a full log under `runtime/test-results/`. Source changes during a run prevent a passing receipt. No test is filtered out by the runner.

Git checkouts pin the tracked file set. Source archives without Git still pin the code, tests, preparation scripts and dependency locks; generated runtime data is excluded from those integrity records.

The symbolic-link boundary test requires OS permission to create a symbolic link. On a restricted Windows token it remains explicitly skipped; the runner does not change host security settings or claim that check passed.
