"""CPU-only inference experiment inside an offline Linux VM; no tool execution."""
import argparse
import json
import os
from pathlib import Path
import resource
import subprocess
import threading
import time
import urllib.error
import urllib.request


def memory():
    return {line.split(':')[0]: int(line.split()[1]) for line in Path('/proc/meminfo').read_text().splitlines() if len(line.split()) == 3}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--memory', type=int, required=True)
    parser.add_argument('--smoke', action='store_true')
    parser.add_argument('--calibration', action='store_true')
    args = parser.parse_args()
    folder = Path('/workspace')
    report = {'model': 'LFM2.5-350M-Q4_K_M', 'runtime': 'llama.cpp b11711', 'memory_mib': args.memory,
              'uid': os.getuid(), 'context_tokens': 1024, 'cpu_threads': 1, 'gpu': False, 'smoke_only':args.smoke,
              'calibration':args.calibration,
              'network': {'interfaces': sorted(p.name for p in Path('/sys/class/net').iterdir()),
                          'routes': Path('/proc/net/route').read_text(), 'dns': Path('/etc/resolv.conf').read_text()},
              'memory_before_kib': memory(), 'cases': [], 'tools_executed': False}
    path = folder/f'result-{args.memory}.json'
    log_path = folder/f'llama-{args.memory}.log'
    server = None
    stop = threading.Event()
    samples = []
    begun = time.monotonic()
    def save():
        path.write_text(json.dumps(report, indent=2, ensure_ascii=True)+'\n')
    def checkpoint(event, **fields):
        with (folder/f'checkpoints-{args.memory}.jsonl').open('a') as stream:
            stream.write(json.dumps({'event': event, 'at': time.time(), **fields})+'\n')
            stream.flush()
            os.fsync(stream.fileno())
    def request(route, payload=None, timeout=90):
        data = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request('http://127.0.0.1:8080'+route, data=data,
                                     headers={'Content-Type':'application/json'})
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return json.load(response)
    def sample():
        while not stop.wait(.1):
            try:
                status = Path(f'/proc/{server.pid}/status').read_text()
                values = {line.split(':')[0]: int(line.split()[1]) for line in status.splitlines() if line.startswith(('VmRSS:', 'VmHWM:', 'VmSize:'))}
                values['available_kib'] = memory()['MemAvailable']
                samples.append(values)
            except (OSError, KeyError):
                pass
    try:
        assert report['uid'] == 1000 and report['network']['interfaces'] == ['lo']
        command = ['/workspace/llama/llama-b11711/llama-server', '-m', '/workspace/model.gguf',
                   '-c', '1024', '-t', '1', '-tb', '1', '-b', '64', '-ub', '64', '-np', '1',
                   '-ngl', '0', '--host', '127.0.0.1', '--port', '8080', '--jinja', '--no-webui',
                   '--no-warmup', '--fit', 'off', '--threads-http', '1']
        report['server_argv'] = command
        checkpoint('starting', memory_mib=args.memory)
        with log_path.open('wb') as log:
            server = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT,
                                      env={**os.environ, 'OMP_NUM_THREADS':'1', 'OPENBLAS_NUM_THREADS':'1',
                                           'LD_LIBRARY_PATH':'/workspace/dependencies:/workspace/llama/llama-b11711'})
            monitor = threading.Thread(target=sample, daemon=True)
            monitor.start()
            deadline = time.monotonic()+90
            while True:
                if server.poll() is not None:
                    raise RuntimeError('Inference server exited: '+str(server.returncode)+'; '+log_path.read_text(errors='replace')[-2500:])
                try:
                    request('/health', timeout=1)
                    break
                except (OSError, urllib.error.URLError):
                    if time.monotonic()>deadline:
                        raise TimeoutError('Model loading deadline')
                    time.sleep(.2)
            report['load_seconds'] = round(time.monotonic()-begun,3)
            checkpoint('loaded', seconds=report['load_seconds'])
            tools = [{'type':'function','function':{'name':'send_message','description':'Send a message to another agent.',
                     'parameters':{'type':'object','properties':{'recipient':{'type':'string'},'text':{'type':'string'}},
                                   'required':['recipient','text'],'additionalProperties':False}}},
                     {'type':'function','function':{'name':'read_file','description':'Read a workspace file.',
                     'parameters':{'type':'object','properties':{'path':{'type':'string'}},'required':['path'],'additionalProperties':False}}}]
            cases = [
                ('arithmetic','Reply with only the answer: 7 + 5.',None,None,lambda m: m.get('content','').strip() == '12'),
                ('message_json','Return only JSON with recipient and text. Send the exact text ready to guest-b.',None,None,
                 lambda m: json.loads(m['content']) == {'recipient':'guest-b','text':'ready'}),
                ('extract_json','Return only JSON with filename and count. The file is notes.txt and the count is 3.',None,None,
                 lambda m: json.loads(m['content']) == {'filename':'notes.txt','count':3}),
                ('unicode_json','Return only JSON with text. Preserve this exact text: café 中文 🚀',None,None,
                 lambda m: json.loads(m['content']) == {'text':'café 中文 🚀'}),
                ('tool_send','Send the message ready to agent guest-b.',tools,None,
                 lambda m: valid_call(m,'send_message',{'recipient':'guest-b','text':'ready'})),
                ('tool_read','Read the file /workspace/notes.txt.',tools,None,
                 lambda m: valid_call(m,'read_file',{'path':'/workspace/notes.txt'})),
                ('tool_no_call','Reply with just the word hello. Do not call any tools.',tools,None,
                 lambda m: not m.get('tool_calls') and m.get('content','').strip().lower()=='hello'),
                ('schema_message','Send exactly the text ready to guest-b. Return JSON.',None,
                 {'type':'json_schema','json_schema':{'name':'message','strict':True,'schema':{'type':'object',
                    'properties':{'recipient':{'type':'string'},'text':{'type':'string'}},'required':['recipient','text'],'additionalProperties':False}}},
                 lambda m: json.loads(m['content']) == {'recipient':'guest-b','text':'ready'}),
            ]
            if args.smoke:
                cases = [case for case in cases if case[0] in ('arithmetic','schema_message')]
            if args.calibration:
                schema = cases[-1][3]
                cases = [
                    ('explicit_schema_message', 'Return a JSON object. Set recipient to "guest-b". Set text to "ready". Copy both strings exactly.',
                     None,schema,lambda m: json.loads(m['content']) == {'recipient':'guest-b','text':'ready'}),
                    ('explicit_tool_message','Call send_message with recipient="guest-b" and text="ready". Use these exact arguments.',
                     tools,None,lambda m: valid_call(m,'send_message',{'recipient':'guest-b','text':'ready'})),
                ]
            for name, prompt, offered, response_format, check in cases:
                payload = {'model':'local','messages':[{'role':'system','content':'Follow instructions precisely. Use a tool only when needed.'},
                           {'role':'user','content':prompt}], 'temperature':0, 'seed':42, 'max_tokens':128, 'stream':False,
                           'cache_prompt':False}
                if args.calibration:
                    payload.update(temperature=.1,top_k=50,repeat_penalty=1.05)
                if offered:
                    payload.update(tools=offered,tool_choice='auto')
                if response_format:
                    payload['response_format'] = response_format
                row = {'name':name,'prompt':prompt,'schema_constrained':bool(response_format),'passed':False}
                started = time.monotonic()
                try:
                    result = request('/v1/chat/completions',payload)
                    message = result['choices'][0]['message']
                    row.update(message=message,usage=result.get('usage'),timings=result.get('timings'),
                               finish_reason=result['choices'][0].get('finish_reason'))
                    try:
                        row['passed'] = bool(check(message))
                    except (ValueError,KeyError,TypeError):
                        row['passed'] = False
                except Exception as error:
                    row['error'] = {'class':type(error).__name__,'message':str(error)[:500]}
                row['wall_seconds'] = round(time.monotonic()-started,3)
                report['cases'].append(row)
                checkpoint('case_completed',name=name,passed=row['passed'],seconds=row['wall_seconds'])
                save()
            report['runtime_passed'] = not any('error' in case for case in report['cases'])
            report['quality_passed'] = all(case['passed'] for case in report['cases'])
            report['quality_score'] = {'passed':sum(case['passed'] for case in report['cases']),'total':len(cases)}
    except Exception as error:
        report.update(runtime_passed=False, error={'class':type(error).__name__,'message':str(error)[:3500]})
    finally:
        if server is not None and server.poll() is None:
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=5)
        stop.set()
        report['server_exit_code'] = server.returncode if server else None
        report['server_peak_rss_kib'] = max((s.get('VmHWM',0) for s in samples),default=0)
        report['server_peak_virtual_kib'] = max((s.get('VmSize',0) for s in samples),default=0)
        report['guest_min_available_kib'] = min((s['available_kib'] for s in samples),default=0)
        report['memory_after_kib'] = memory()
        report['child_maxrss_kib'] = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
        report['elapsed_seconds'] = round(time.monotonic()-begun,3)
        checkpoint('finished',runtime_passed=report.get('runtime_passed'),quality_passed=report.get('quality_passed'))
        save()
    print(json.dumps({'report':str(path),'runtime_passed':report['runtime_passed'],'quality_score':report.get('quality_score'),'error':report.get('error')}))


def valid_call(message,name,arguments):
    calls = message.get('tool_calls') or []
    return len(calls)==1 and calls[0]['function']['name']==name and json.loads(calls[0]['function']['arguments'])==arguments


if __name__=='__main__':
    main()
