import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from agenticvm.independent_lab import enroll
from agenticvm.independent_recovery import require_clean_history
if __name__=='__main__':
    require_clean_history()
    raise SystemExit(enroll())
