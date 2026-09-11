# pytest 配置：将 ml/scripts 加入导入路径
# Add ml/scripts to sys.path.

import sys
from pathlib import Path

ML_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_PATH = ML_ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS_PATH))
