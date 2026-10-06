# -*- coding: utf-8 -*-
"""
短信/彩信提取器
数据库路径: /data/data/com.android.providers.telephony/databases/mmssms.db
表: sms, mms
"""

from typing import Any, Dict, List

from config import ANDROID_PATHS
from extractors.base import BaseExtractor
from parsers.sqlite_parser import SQLiteParser
from utils.helpers import timestamp_to_str

# 短信类型（箱）
SMS_BOX = {
    1: "收件箱",
    2: "已发送",
    3: "草稿",
    4: "发件箱",
    5: "发送失败",
    6: "待发送",
}

# 彩信类型
MMS_MSG_BOX = {
    1: "收件箱",
    2: "已发送",
    3: "草稿",
    4: "发件箱",
}


class SMSExtractor(BaseExtractor):
    name = "sms"
    description = "短信与彩信"
    requires_root = True

    def extract(self) -> Dict[str, Any]:
        sms_records: List[Dict[str, Any]] = []
        mms_records: List[Dict[str, Any]] = []

        db_path = self._pull_db(ANDROID_PATHS["sms_mms"], "mmssms.db")
        if not db_path:
            return {"sms": [], "mms": [], "summary": {"sms": 0, "mms": 0}, "files": []}

        try:
            with SQLiteParser(db_path) as parser:
                # ---- 提取短信 ----
                if parser.table_exists("sms"):
                    rows = parser.query("SELECT * FROM sms ORDER BY date DESC")
                    for row in rows:
                        msg_type = row.get("type", 0)
                        record = {
                            "id": row.get("_id"),
                            "号码": row.get("address", ""),
                            "内容": row.get("body", "") or "",
                            "类型": SMS_BOX.get(msg_type, f"未知({msg_type})"),
                            "日期": timestamp_to_str(row.get("date")),
                            "是否已读": "已读" if row.get("read") else "未读",
                            "状态": self._sms_status(row.get("status")),
                            "SIM卡": row.get("sub_id", "未知"),
                            "服务中心": row.get("service_center", "") or "",
                            "锁定": "是" if row.get("locked") else "否",
                        }
                        sms_records.append(record)

                # ---- 提取彩信 ----
                if parser.table_exists("mms"):
                    rows = parser.query("SELECT * FROM mms ORDER BY date DESC")
                    for row in rows:
                        msg_box = row.get("msg_box", 0)
                        # 彩信日期是秒级
                        date_val = row.get("date")
                        if date_val and date_val < 1e11:
                            date_val = date_val * 1000
                        record = {
                            "id": row.get("_id"),
                            "主题": row.get("sub", "") or "",
                            "类型": MMS_MSG_BOX.get(msg_box, f"未知({msg_box})"),
                            "日期": timestamp_to_str(date_val),
                            "是否已读": "已读" if row.get("read") else "未读",
                            "大小(字节)": row.get("m_size", 0),
                            "内容类型": row.get("ct_cls", "") or "",
                            "状态": self._mms_status(row.get("st")),
                        }
                        mms_records.append(record)
        except Exception as e:
            from utils.logger import get_logger
            get_logger().warning(f"解析短信数据库失败: {e}")

        return {
            "sms": sms_records,
            "mms": mms_records,
            "summary": {
                "sms": len(sms_records),
                "mms": len(mms_records),
                "total": len(sms_records) + len(mms_records),
            },
            "files": [db_path],
        }

    @staticmethod
    def _sms_status(status) -> str:
        mapping = {0: "无", 1: "等待中", 2: "已发送", 3: "已接收", 4: "发送失败"}
        return mapping.get(status, str(status))

    @staticmethod
    def _mms_status(status) -> str:
        mapping = {0: "已接收", 1: "已发送", 2: "草稿", 3: "发送中", 4: "发送失败"}
        return mapping.get(status, str(status))
