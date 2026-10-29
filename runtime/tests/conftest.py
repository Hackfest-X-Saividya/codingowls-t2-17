import sys
from pathlib import Path

# checker.py and server.py are plain scripts in runtime/
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
