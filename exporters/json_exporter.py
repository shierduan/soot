# -*- coding: utf-8 -*-
"""
JSON 导出器
将提取结果导出为 JSON 文件。
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict

from utils.helpers import CST


class JSONExporter:
    """JSON 导出器"""

    @staticmethod
    def export(data: Dict[str, Any], output_path: str) -> str:
        """导出数据为 JSON 文件"""
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)

        export_data = {
            "export_time": datetime.now(CST).strftime("%Y-%m-%d %H:%M:%S"),
            "data": data,
        }

        with open(output, "w", encoding="utf-8") as f:
            json.dump(export_data, f, ensure_ascii=False, indent=2, default=str)

        return str(output)
