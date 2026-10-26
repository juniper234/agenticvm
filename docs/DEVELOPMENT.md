# Development

The repository keeps first-party source and pinned dependency descriptions. Prepare tools and guest assets locally; downloaded runtimes, images, models and generated state are ignored by Git.

## Python control layer

Create a Python 3.13 virtual environment, then install the checkout with `python -m pip install -e .`. The core package declares no mandatory third-party Python dependencies. Its optional `transfer` extra pins PyNaCl, cffi and pycparser for the corresponding transfer features.

Run `python -m unittest discover -s tests -v` from the checkout after installing it. Host tests exercise contracts and local fixtures; native VM campaigns are separate scripts. Scripts that prepare or download tools are explicit actions and are not run by the test command merely to obtain missing dependencies.

## Windows desktop

The desktop projects target .NET 9 for Windows. With an appropriate local SDK:

```powershell
dotnet publish desktop/AgenticVM.Desktop/AgenticVM.Desktop.csproj -c Release -r win-x64 --self-contained true -o dist/AgenticVM-Desktop
```

This builds the shell. A complete portable delivery also needs its Python control package, runtime, QEMU and prepared guest assets. The scripts under `scripts/` document the prepared workspace layout; a compiled shell alone is not a complete guest runtime.

## Tool and guest preparation

`tools/build-tools-lock.json` and the other tool locks describe pinned sources and checksums. `scripts/prepare-build-tools.py --check` checks the prepared local Windows build tools; `--download` explicitly permits its supported downloads. Other preparation scripts are platform-specific. Read their arguments and expected layout before using them.

Linux desktop preparation, Android preparation and Windows guest preparation are distinct paths. Windows evaluation media is obtained separately under its own terms. No VM disks, media images, machine credentials or local model weights are included in this repository.

## Changes and evidence

Run checks appropriate to the changed control/backend layer. Native tests must use an explicitly selected, owned guest and the existing resource and ownership controls. Preserve a failed run's local diagnostics rather than changing an assertion to turn it into a pass.

Keep generated receipts, screenshots, session records, exchange folders, tokens and provider credentials outside the Git index. The README logo is a project asset; local desktop screenshots are not part of this source publication.
