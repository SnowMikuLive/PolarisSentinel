"""pytest 公共配置：将 ml/scripts 加入导入路径，使测试可直接 import 训练脚本。
Shared pytest setup: add ml/scripts to sys.path so tests can import training modules.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
