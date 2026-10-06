# -*- coding: utf-8 -*-
"""
CSV 导出器
将提取结果导出为 CSV 文件（每个数据表一个 CSV）。
"""

import csv
from pathlib import Path
from typing import Any, Dict, List

from utils.logger import get_logger

logger = get_logger("exporter")


class CSVExporter:
    """CSV 导出器"""

    @staticmethod
    def export(data: Dict[str, Any], output_dir: str) -> List[str]:
        """
        导出数据为多个 CSV 文件。
        data 中每个列表值对应一个 CSV 文件。
        返回生成的文件路径列表。
        """
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        created_files: List[str] = []

        for key, value in data.items():
            if isinstance(value, list) and value and isinstance(value[0], dict):
                filepath = output_dir / f"{key}.csv"
                CSVExporter._write_csv(value, str(filepath))
                created_files.append(str(filepath))
            elif isinstance(value, dict):
                # 嵌套字典中可能有列表
                for sub_key, sub_value in value.items():
                    if isinstance(sub_value, list) and sub_value and isinstance(sub_value[0], dict):
                        filepath = output_dir / f"{key}_{sub_key}.csv"
                        CSVExporter._write_csv(sub_value, str(filepath))
                        created_files.append(str(filepath))

        return created_files

    @staticmethod
    def _write_csv(records: List[Dict[str, Any]], filepath: str):
        """将记录列表写入 CSV"""
        if not records:
            return
        # 收集所有字段
        fieldnames: List[str] = []
        seen = set()
        for record in records:
            for k in record.keys():
                if k not in seen:
                    seen.add(k)
                    fieldnames.append(k)

        with open(filepath, "w", encoding="utf-8-sig", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for record in records:
                # 处理非字符串值
                row = {k: v if isinstance(v, str) else str(v) for k, v in record.items()}
                writer.writerow(row)
