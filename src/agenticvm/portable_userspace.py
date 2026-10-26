"""Explicit older-distro adapter; never replace the guest's system libraries."""
from __future__ import annotations
import copy
import hashlib
import json


def adapt_native_config(config):
    config = copy.deepcopy(config)
    for item in config['write_files']:
        if item['path'] == '/etc/garden/bootstrap.sh':
            old = 'if [ ! -x /usr/bin/python3 ]; then'
            if item['content'].count(old) != 1:
                raise ValueError('Reviewed native dependency bootstrap changed')
            item['content'] = item['content'].replace(old, 'if true; then')
        if item['path'] != '/etc/garden/bootstrap.py':
            continue
        text = item['content']
        old = "python = '/usr/bin/python3' if Path('/usr/bin/python3').exists() else str(HOME / 'runtime/python')"
        if text.count(old) != 1:
            raise ValueError('Reviewed native interpreter selection changed')
        text = text.replace(old, "python = str(HOME / 'runtime/python') if (HOME / 'runtime/python').exists() else '/usr/bin/python3'")
        marker = "                    child = subprocess.run(['/usr/bin/systemctl', 'start', 'garden-native.service'],"
        if text.count(marker) != 1:
            raise ValueError('Reviewed native activation boundary changed')
        wrapper = '''#!/bin/sh
runtime_dir=/var/lib/garden/runtime
exec "$runtime_dir/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2" --library-path "$runtime_dir/lib/x86_64-linux-gnu:/var/lib/garden/dependencies:/var/lib/garden/llama/llama-b11711" /var/lib/garden/llama/llama-b11711/llama-server.elf "$@"
'''
        injection = """                    server = HOME / 'llama/llama-b11711/llama-server'
                    if server.read_bytes()[:4] != b'\\x7fELF':
                        raise ValueError('Portable inference adapter expected the verified original ELF')
                    server.rename(server.with_name('llama-server.elf'))
                    server.write_text(WRAPPER)
                    os.chown(server, 1000, 1000)
                    server.chmod(0o500)
""".replace('WRAPPER', repr(wrapper))
        text = text.replace(marker, injection + marker)
        compile(text, '<declared-portable-native-bootstrap>', 'exec')
        item['content'] = text
    return config


def transformed_input_pins(config):
    return {item['path']: hashlib.sha256(item['content'].encode()).hexdigest() for item in config['write_files']}
