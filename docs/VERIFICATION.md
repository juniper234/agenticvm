# Source publication verification

The public source snapshot was prepared on **26 October 2026**. It was copied into a separate directory with no detected source changes during copying or the reported test runs. The original development workspace and native VM state were not modified to make this publication.

## Source and privacy checks

- All 404 included Python files parsed successfully.
- The exact Git index was checked for personal paths, unrelated project names, credential literals, private keys, provider/GitHub tokens, live tunnel links and excluded artifact types.
- Scanner matches were reviewed: synthetic URL/authentication-rejection fixtures and public Debian signing-key metadata. No personal-project or credential finding remained in the selected publication contents.
- Local runtime directories, credentials, VM disks, operating-system media, downloaded tools, local model weights, handover records, raw evidence, screenshots, third-party research checkouts and separate DSH plugin projects are excluded.
- The README logo is the existing AgenticVM project asset. Its published bytes are checked against the local project logo.

## Host suite result and limitations

The frozen-source run discovered **505 reported test cases**: **2 failures, 10 errors and 1 skip**. This is **not a clean full-suite pass**. The initial run also exposed test-environment setup issues; rerunning with a writable shorter temporary directory and an empty local `runtime` directory removed those setup failures without changing source assertions.

Remaining blockers in this source-only environment:

- Missing optional `libtorrent`, `nacl` / PyNaCl, `pefile` and `pyghmi` dependencies.
- Missing prepared PXE build files and Windows application-runtime metadata, which are intentionally outside Git.
- Three Windows guest checks rejected the deep publication checkout because of private socket path limits.
- One symbolic-link boundary check was skipped because this Windows token cannot create symbolic links.

Some test modules cannot load until their optional dependencies are available, so the reported discovery count does not certify that every possible test ran. The private raw logs were retained locally. No native VM campaign, provider inference or physical-device acceptance was performed for this source publication.
