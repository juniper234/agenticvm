"""Generate folder-specific MCP configuration; never alter a harness profile."""
from pathlib import Path
import json

ROOT = Path(__file__).resolve().parents[1]


def configuration(root):
    return {'mcpServers': {'agenticvm-desktop': {'command': str(root/'tools/python-runtime/3.13.16/python.exe'),
        'args': ['-I','-B','-m','agenticvm.desktop_mcp']}}}


if __name__ == '__main__':
    target = ROOT/'mcp.beta.json'
    # This generated local example contains paths only, never launch tokens.
    target.write_text(json.dumps(configuration(ROOT),indent=2)+'\n',encoding='utf-8')
    print('MCP configuration saved: ' + str(target))
    print('Start-AgenticVM-Service.cmd starts the service. Copy the server entry into your agent client.')
