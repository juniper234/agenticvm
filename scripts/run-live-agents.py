"""Native executable entry point for persistent encrypted Linux agent contact."""
from pathlib import Path
import sys

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from agenticvm.live_runtime import main

if __name__ == '__main__':
    import signal
    if hasattr(signal,'SIGBREAK'):
        signal.signal(signal.SIGBREAK,signal.default_int_handler)
    try:
        raise SystemExit(main())
    except Exception as error:
        import json
        print(json.dumps({'ok':False,'error':type(error).__name__,'message':str(error)[:500]}))
        raise SystemExit(1)
