# Source publication verification

The public source snapshot was prepared on **26 October 2026**. It was copied into a separate directory with no detected source changes during copying or the reported test runs. The original development workspace and native VM state were not modified to make this publication.

## Source and privacy checks

- All 408 included Python files parsed successfully, including the added test/setup source.
- The exact Git index was checked for personal paths, unrelated project names, credential literals, private keys, provider/GitHub tokens, live tunnel links and excluded artifact types.
- Scanner matches were reviewed: synthetic URL/authentication-rejection fixtures and public Debian signing-key metadata. No personal-project or credential finding remained in the selected publication contents.
- Local runtime directories, credentials, VM disks, operating-system media, downloaded tools, local model weights, handover records, raw evidence, screenshots, third-party research checkouts and separate DSH plugin projects are excluded.
- The README logo is the existing AgenticVM project asset. Its published bytes are checked against the local project logo.

## Test fixes and current result

The final repaired suite reports **546 tests: 545 passed, zero failures, zero errors and one platform skip**. Full normal-order and deterministic shuffled-order runs also passed at 545 cases; the final reverse-order run includes the added source-archive integrity check. No source changed during these passing runs. Focused regressions, active-development-copy checks and repeated offline preparation also passed.

The fixes cover:

- The control CLI now scopes and restores its default socket-root environment on reuse, normal return and errors.
- Importing the Windows supervisor no longer changes the caller's socket-root environment. Executing the supervisor still configures its intended default before running.
- Windows unattended-selector tests construct their own bounded fixture inputs, including digest and unapproved-image denial checks; they do not require a real prepared Windows installation.
- Pinned dependency preparation supplies the actual libtorrent, PyNaCl, firmware/PE and IPMI dependencies even to isolated subprocesses.
- The strict prepared-PXE/firmware assertions remain in the suite. Their build assets were imported only after size/hash verification against the committed test-asset lock.
- Preparation rejects archive traversal/links/collisions, preserves changed files and safely reuses the expected Windows interpreter configuration in LF or CRLF form.

The earlier source-only discovery reported 505 cases with missing dependencies/assets and environment failures. Those failed receipts/logs were retained locally. Additional encrypted-transfer cases can now load, and new regression cases explain the increased count. No previously failing asset assertion was removed, filtered out or converted into a passing stub.

## Remaining limits

One symbolic-link boundary check remains explicitly skipped because the Windows test token lacks permission to create a symbolic link. Host security settings were not changed to bypass that limitation. The real directory-junction refusal checks still run.

The pinned firmware helper emits its existing `pkg_resources` deprecation warning; its compatible setuptools version is pinned. Generated dependencies, images, test identities and raw receipts stay outside Git. These host checks include real loopback protocol/asset tests but do not establish native VM, provider/model, physical-device or 4 GB host acceptance. See [TESTING.md](TESTING.md) to reproduce the setup and ordered runs.
