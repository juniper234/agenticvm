"""Preserve raw guest observations and summarize runtime versus task accuracy."""
from pathlib import Path
import hashlib
import json
import shutil
import statistics
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from agenticvm.resources import memory_status
from agenticvm.state import StateStore


def main():
    folder=ROOT/'runtime/local-model-test'
    evidence=[]
    target=ROOT/'docs/validation'
    for directory in sorted(folder.glob('evidence-*')):
        for path in directory.glob('result-*.json'):
            result=json.loads(path.read_text(encoding='utf-8'))
            copied=target/('local-model-'+directory.name+'.json')
            shutil.copy2(path,copied)
            rows=result.get('cases',[])
            speeds=[row['timings']['predicted_per_second'] for row in rows if row.get('timings')]
            evidence.append({'source':str(path.relative_to(ROOT)), 'public_report':str(copied.relative_to(ROOT)),
                'sha256':hashlib.sha256(copied.read_bytes()).hexdigest(),
                'guest_ram_mib':result['memory_mib'], 'smoke_only':result.get('smoke_only',False),
                'calibration':result.get('calibration',False), 'runtime_passed':result['runtime_passed'],
                'strict_quality_score':result.get('quality_score'),
                'server_peak_rss_mib':round(result.get('child_maxrss_kib',0)/1024,2),
                'load_seconds':result.get('load_seconds'), 'elapsed_seconds':result.get('elapsed_seconds'),
                'median_decode_tokens_per_second':round(statistics.median(speeds),2) if speeds else None,
                'zram_logical_swap_used_after_test_kib':result.get('memory_after_kib',{}).get('SwapTotal',0)-result.get('memory_after_kib',{}).get('SwapFree',0),
                'error':result.get('error'), 'owned_vm_stopped':json.loads((directory/'stop.json').read_text())['status']=='stopped'})
    state=StateStore(folder/'vm').load()
    report={'schema':'agenticvm.local-inference-experiment.v1', 'model':'LiquidAI/LFM2.5-350M-GGUF Q4_K_M',
            'preparation':json.loads((folder/'preparation.json').read_text()),
            'guest_cpu':json.loads((folder/'guest-cpu.json').read_text()), 'host_memory_at_summary':memory_status(),
            'physical_4gb_host_tested':False, 'normal_product_images_changed':False,
            'guest_model_calls_executed_tools':False, 'latest_test_vm_registered':state['registered'],
            'experiments':evidence,
            'interpretation':'Runtime feasibility and strict task accuracy are separate. Formatting-only failures remain failures for machine consumption. Schema-constrained output can still contain incorrect field values. Smoke tests do not establish sustained stability or complete agent performance.',
            'limits':['Synthetic tiny task suite, not a general intelligence benchmark.',
                      'One virtual CPU with the recorded conservative feature set; performance is hardware-dependent.',
                      '256 MiB run uses disk-backed memory-mapped weights and compressed zram swap; it is not fully resident inference.',
                      'No model-directed OS execution or encrypted VM-to-VM model integration has been enabled.',
                      'Test-only control image permits 2 GiB virtual address space while physical guest allocation stays bounded.']}
    destination=target/'local-model-test-report.json'
    destination.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'report':str(destination),'experiments':len(evidence),'latest_vm_stopped':not state['registered']}))


if __name__=='__main__':
    main()
