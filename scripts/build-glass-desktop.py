"""Build the native glass shell with the existing project-local .NET SDK."""
from pathlib import Path
import argparse
import os
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, default=Path('dist/AgenticVM-Glass'))
    args = parser.parse_args()
    sdk = ROOT / 'tools/dotnet/sdk/dotnet.exe'
    if not sdk.is_file():
        raise RuntimeError('The project-local .NET 9 SDK is missing')
    env = os.environ.copy()
    env.update(DOTNET_CLI_HOME=str(ROOT / 'tools/dotnet/home'),
        NUGET_PACKAGES=str(ROOT / 'tools/nuget-packages'),
        DOTNET_SKIP_FIRST_TIME_EXPERIENCE='1', DOTNET_CLI_TELEMETRY_OPTOUT='1',
        DOTNET_GENERATE_ASPNET_CERTIFICATE='false',
        TEMP=str(ROOT / 'runtime/build-temp'), TMP=str(ROOT / 'runtime/build-temp'),
        APPDATA=str(ROOT / 'runtime/build-appdata'), LOCALAPPDATA=str(ROOT / 'runtime/build-localappdata'))
    for name in ('TEMP', 'APPDATA', 'LOCALAPPDATA'):
        Path(env[name]).mkdir(parents=True, exist_ok=True)
    project = 'desktop/AgenticVM.Desktop/AgenticVM.Desktop.csproj'
    commands = [
        [str(sdk), 'restore', project, '--configfile', str(ROOT / 'tools/NuGet.Config'), '--nologo'],
        [str(sdk), 'build', project, '--no-restore', '-c', 'Release', '-o', str(args.output), '--nologo', '-v', 'minimal'],
    ]
    for command in commands:
        result = subprocess.run(command, cwd=ROOT, env=env)
        if result.returncode:
            return result.returncode
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
