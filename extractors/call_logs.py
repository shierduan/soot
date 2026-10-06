# -*- coding: utf-8 -*-
"""
通话记录提取器
数据库路径: /data/data/com.android.providers.contacts/databases/calllog.db
表: calls
"""

from typing import Any, Dict, List

from config import ANDROID_PATHS
from extractors.base import BaseExtractor
from parsers.sqlite_parser import SQLiteParser
from utils.helpers import timestamp_to_str

# 通话类型映射
CALL_TYPES = {
    1: "来电",
    2: "去电",
    3: "未接",
    4: "语音信箱",
    5: "拒接",
    6: "已接来电(外部)",
    7: "来电(外部)",
}

# SIM 卡类型
PHONE_ACCOUNTS = {
    0: "SIM1",
    1: "SIM2",
}


class CallLogExtractor(BaseExtractor):
    name = "call_logs"
    description = "通话记录"
    requires_root = True

    def extract(self) -> Dict[str, Any]:
        records: List[Dict[str, Any]] = []
        db_path = self._pull_db(ANDROID_PATHS["call_log"], "calllog.db")

        if not db_path:
            return {"records": [], "summary": {"total": 0}, "files": []}

        try:
            with SQLiteParser(db_path) as parser:
                if not parser.table_exists("calls"):
                    return {"records": [], "summary": {"total": 0}, "files": [db_path]}

                rows = parser.query(
                    "SELECT * FROM calls ORDER BY date DESC"
                )

                for row in rows:
                    call_type = row.get("type", 0)
                    duration = row.get("duration", 0) or 0
                    record = {
                        "id": row.get("_id"),
                        "号码": row.get("number", ""),
                        "姓名": row.get("name", "") or "",
                        "类型": CALL_TYPES.get(call_type, f"未知({call_type})"),
                        "日期": timestamp_to_str(row.get("date")),
                        "时长(秒)": duration,
                        "时长(可读)": self._format_duration(duration),
                        "是否新": "是" if row.get("new") else "否",
                        "SIM卡": PHONE_ACCOUNTS.get(row.get("phone_id", 0), "未知"),
                        "国家ISO": row.get("countryiso", "") or "",
                        "地理位置": row.get("geocoded_location", "") or "",
                    }
                    records.append(record)
        except Exception as e:
            from utils.logger import get_logger
            get_logger().warning(f"解析通话记录失败: {e}")

        summary = {
            "total": len(records),
            "incoming": sum(1 for r in records if r["类型"] == "来电"),
            "outgoing": sum(1 for r in records if r["类型"] == "去电"),
            "missed": sum(1 for r in records if r["类型"] == "未接"),
        }

        return {
            "records": records,
            "summary": summary,
            "files": [db_path],
        }

    @staticmethod
    def _format_duration(seconds: int) -> str:
        """将秒数格式化为可读时长"""
        if not seconds:
            return "0秒"
        h = seconds // 3600
        m = (seconds % 3600) // 60
        s = seconds % 60
        parts = []
        if h:
            parts.append(f"{h}小时")
        if m:
            parts.append(f"{m}分")
        if s:
            parts.append(f"{s}秒")
        return "".join(parts)
