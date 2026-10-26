"""The pinned CPU model server. Runs inside a Linux guest, never on Windows."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
import urllib.request

MODEL_NAME = 'LFM2.5-350M-Q4_K_M'
MODEL_SHA = '7e6f72643caafc9a68256686638c4d7916f2cec76d1df478d4c3ddcd95a6aed4'
BASE = Path('/workspace')


def text(value):
    if not isinstance(value,str) or not 1 <= len(value.strip()) <= 160 or any(ord(c)<32 for c in value):
        raise ValueError('Model output must be one short, nonempty line')
    return value.strip()


class LocalLFM:
    def __init__(self):
        self.process = self.log = None
        self.ready = False
        self.verified = False
        self.calls = 0
        self.peak_rss_kib = 0

    def start(self):
        with (BASE/'model.gguf').open('rb') as stream:
            if hashlib.file_digest(stream,'sha256').hexdigest() != MODEL_SHA:
                raise ValueError('The installed LFM weights changed')
        self.verified = True
        self.log = (BASE/'peer/model.log').open('wb')
        argv = [str(BASE/'llama/llama-b11711/llama-server'),'-m',str(BASE/'model.gguf'),
                '-c','1024','-t','1','-tb','1','-b','64','-ub','64','-np','1','-ngl','0',
                '--host','127.0.0.1','--port','8080','--jinja','--no-webui','--no-warmup',
                '--fit','off','--threads-http','1']
        self.process = subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=self.log,stderr=subprocess.STDOUT,
            env={**os.environ,'LD_LIBRARY_PATH':'/workspace/dependencies:/workspace/llama/llama-b11711',
                 'MALLOC_ARENA_MAX':'1','OMP_NUM_THREADS':'1','OPENBLAS_NUM_THREADS':'1'})
        deadline = time.monotonic()+90
        while time.monotonic()<deadline:
            self.ensure_alive()
            try:
                with urllib.request.urlopen('http://127.0.0.1:8080/health',timeout=1) as response:
                    if response.status==200:
                        self.ready = True
                        return
            except OSError:
                time.sleep(.2)
        raise TimeoutError('LFM startup exceeded its 90 second deadline')

    def ensure_alive(self):
        if self.process and self.process.poll() is not None:
            tail = (BASE/'peer/model.log').read_text(errors='replace')[-1800:]
            raise RuntimeError('LFM server exited: '+str(self.process.returncode)+'; '+tail)

    def generate(self,prompt):
        self.ensure_alive()
        if not self.ready or self.calls>=16:
            raise RuntimeError('LFM is unavailable or this bounded introduction exhausted its call budget')
        self.calls += 1
        schema = {'type':'object','properties':{'text':{'type':'string','minLength':1,'maxLength':160}},
                  'required':['text'],'additionalProperties':False}
        request = {'model':'local','messages':[
            {'role':'system','content':'You are a small helpful agent. Write a short, friendly message. Return JSON only.'},
            {'role':'user','content':prompt}],
            'temperature':.2,'top_k':50,'repeat_penalty':1.05,'seed':42,'max_tokens':48,'cache_prompt':False,
            'response_format':{'type':'json_schema','json_schema':{'name':'message','strict':True,'schema':schema}}}
        req = urllib.request.Request('http://127.0.0.1:8080/v1/chat/completions',
            data=json.dumps(request).encode(),headers={'Content-Type':'application/json'})
        begun = time.monotonic()
        with urllib.request.urlopen(req,timeout=150) as response:
            data = response.read(65537)
        if len(data)>65536:
            raise ValueError('Model API response exceeds its bound')
        result = json.loads(data)
        choice = result['choices'][0]
        if choice.get('finish_reason') != 'stop':
            raise ValueError('LFM output was truncated; no canned replacement is permitted')
        raw = choice['message']['content']
        parsed = json.loads(raw)
        if not isinstance(parsed,dict) or set(parsed) != {'text'}:
            raise ValueError('Unexpected LFM output schema')
        generated = text(parsed['text'])
        predicted = result.get('timings',{}).get('predicted_n') or result.get('usage',{}).get('completion_tokens')
        if type(predicted) is not int or predicted<1:
            raise ValueError('LFM returned no evidence of generated tokens')
        return {'text':generated,'raw_content':raw,'completion_tokens':predicted,
                'prompt_sha256':hashlib.sha256(prompt.encode()).hexdigest(),
                'text_sha256':hashlib.sha256(generated.encode()).hexdigest(),
                'seconds':round(time.monotonic()-begun,3),'timings':result.get('timings',{})}

    def snapshot(self):
        self.ensure_alive()
        memory = {}
        if self.process:
            try:
                for line in Path(f'/proc/{self.process.pid}/status').read_text().splitlines():
                    if line.startswith(('VmRSS:','VmHWM:','VmSize:')):
                        memory[line.split(':')[0]] = int(line.split()[1])
                self.peak_rss_kib = max(self.peak_rss_kib,memory.get('VmHWM',0))
            except FileNotFoundError:
                self.ensure_alive()
        return {'name':MODEL_NAME,'weights_sha256':MODEL_SHA,'weights_verified_inside_vm':self.verified,
                'ready':self.ready,'server_pid':self.process.pid if self.process else None,
                'server_alive':bool(self.process and self.process.poll() is None),'cpu_threads':1,
                'context_tokens':1024,'gpu':False,'calls_started':self.calls,'server_memory_kib':memory,
                'peak_server_rss_kib':self.peak_rss_kib,'execution_location':'Linux guest',
                'executable':os.readlink(f'/proc/{self.process.pid}/exe') if self.process else None,
                'argv':Path(f'/proc/{self.process.pid}/cmdline').read_bytes().decode().rstrip('\0').split('\0') if self.process else [],
                'http_scope':'127.0.0.1 inference API inside this VM only'}

    def close(self):
        self.ready = False
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(5)
        if self.log:
            self.log.close()
