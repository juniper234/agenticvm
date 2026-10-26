"""Package accepted guest artifacts into a standalone offline HTML game."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
from uuid import UUID
import zipfile

ROOT=Path(__file__).resolve().parents[1]


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--run',required=True)
    args=parser.parse_args()
    if str(UUID(args.run))!=args.run:raise ValueError('Use the canonical run UUID')
    folder=ROOT/'runtime/pong-agent-runs'/args.run
    report=json.loads((folder/'report.json').read_text(encoding='utf-8'))
    if not report['passed']:raise ValueError('Only accepted and cleaned-up game runs can be packaged')
    expected=report['worker']['hashes']
    if set(expected)!= {'index.html','engine.js','view.js','logic.js','config.js'}:raise ValueError('Unexpected game inventory')
    sources={}
    for name,sha in expected.items():
        path=folder/'game'/name
        content=path.read_bytes()
        if hashlib.sha256(content).hexdigest()!=sha:raise ValueError('Guest artifact changed: '+name)
        sources[name]=content.decode('utf-8')
    output=ROOT/'dist'/('Pong-'+args.run[:8])
    output.mkdir(parents=True,exist_ok=False)
    (output/'source').mkdir()
    for name in sources:shutil.copy2(folder/'game'/name,output/'source'/name)
    page=sources['index.html']
    for name in ('config.js','logic.js','engine.js','view.js'):
        marker='<script src="'+name+'"></script>'
        if page.count(marker)!=1 or '</script' in sources[name].lower():raise ValueError('Unexpected script packaging boundary')
        page=page.replace(marker,'<script>\n'+sources[name]+'\n</script>')
    (output/'index.html').write_text(page,encoding='utf-8')
    (output/'Open-Pong.cmd').write_bytes(b'@echo off\r\nstart "" "%~dp0index.html"\r\n')
    (output/'README.txt').write_text('Pong\n\nDouble-click index.html or Open-Pong.cmd. No installation or Internet connection is required.\n'
        'Click Start. You control the left paddle with W/S, arrow keys, mouse or touch.\n'
        'Space pauses/resumes. R or Restart resets the game. First to five wins.\n\n'
        'Built by two 512 MiB offline Linux VM agents using local LFM2.5-350M models.\n'
        'The canvas engine, UI and tests were supplied. The worker created arithmetic components,\n'
        'with any deterministic test-driven repairs disclosed in provenance.json.\n'
        'The orchestrator independently tested and accepted matching guest artifact hashes.\n',encoding='utf-8')
    provenance={'run_id':args.run,'guest_artifact_sha256':expected,'standalone_html_sha256':hashlib.sha256((output/'index.html').read_bytes()).hexdigest(),
                'packaging_performed_by':'host controller after guest acceptance','memory_mib_per_agent_vm':512,
                'supplied_canvas_scaffold':True,'formula_origins':report.get('formula_origins'),
                'orchestrator_checks':report['orchestrator']['checks'],'rounds':report['orchestrator']['rounds'],
                'model':'LFM2.5-350M-Q4_K_M','communication':'mutually authenticated TLS 1.3 over direct virtual serial',
                'physical_4gb_host_tested':False}
    (output/'provenance.json').write_text(json.dumps(provenance,indent=2)+'\n',encoding='utf-8')
    archive=output.with_suffix('.zip')
    with zipfile.ZipFile(archive,'x',compression=zipfile.ZIP_DEFLATED) as zipped:
        for path in output.rglob('*'):
            if path.is_file():zipped.write(path,path.relative_to(output))
    print(json.dumps({'ready':True,'directory':str(output),'index':str(output/'index.html'),'zip':str(archive)}))


if __name__=='__main__':main()
