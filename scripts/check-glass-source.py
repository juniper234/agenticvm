"""Catch missing UI hooks/assets before starting the native app."""
from collections import Counter
from html.parser import HTMLParser
from pathlib import Path
import ast
import json
import re

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / 'src/agenticvm/web'


class Document(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids, self.assets = [], []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if 'id' in attrs:
            self.ids.append(attrs['id'])
        for name in ('src', 'href'):
            if attrs.get(name, '').startswith('/'):
                self.assets.append(attrs[name])


document = Document()
document.feed((WEB / 'index.html').read_text(encoding='utf-8-sig'))
hooks = set()
for name in ('app.js', 'glass-ui.js', 'settings.js'):
    hooks.update(re.findall(r"(?:\$|el)\('([^']+)'\)", (WEB / name).read_text(encoding='utf-8')))
missing = sorted(hooks - set(document.ids))
duplicates = [name for name, count in Counter(document.ids).items() if count > 1]
assets = [name for name in document.assets if not (WEB / name[1:]).is_file()]
for relative in ('src/agenticvm/windows_desktop.py', 'guest/windows_desktop_agent.py', 'scripts/prepare-windows-desktop.py',
        'src/agenticvm/control_client.py','src/agenticvm/control_cli.py','src/agenticvm/desktop_mcp.py',
        'scripts/windows-desktop-supervisor.py','scripts/start-control-service.py','scripts/update-windows-guest-tools.py'):
    ast.parse((ROOT / relative).read_text(encoding='utf-8-sig'))
report = {'missing_ids': missing, 'duplicate_ids': duplicates, 'missing_assets': assets,
    'python_syntax': 'passed', 'ok': not (missing or duplicates or assets)}
print(json.dumps(report))
raise SystemExit(0 if report['ok'] else 1)
