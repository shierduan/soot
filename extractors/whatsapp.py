# -*- coding: utf-8 -*-
"""
WhatsApp 数据提取器
数据库路径:
  - /data/data/com.whatsapp/databases/msgstore.db  (消息)
  - /data/data/com.whatsapp/databases/wa.db        (联系人)
"""

from typing import Any, Dict, List

from config import ANDROID_PATHS
from extractors.base import BaseExtractor
from parsers.sqlite_parser import SQLiteParser
from utils.helpers import timestamp_to_str

# WhatsApp 消息类型
WHATSAPP_MSG_TYPES = {
    0: "文本",
    1: "图片",
    2: "音频",
    3: "视频",
    4: "联系人",
    5: "位置",
    7: "系统消息",
    8: "文档",
    9: "已读回执",
    10: "群组创建",
    11: "群组描述",
    13: "群组主题",
    14: "群组图片",
    15: "付款",
    16: "已加密",
    20: "贴纸",
    21: "GIF",
}


class WhatsAppExtractor(BaseExtractor):
    name = "whatsapp"
    description = "WhatsApp 消息"
    requires_root = True

    def extract(self) -> Dict[str, Any]:
        messages: List[Dict[str, Any]] = []
        contacts: List[Dict[str, Any]] = []

        # 拉取消息数据库
        msgstore_path = self._pull_db(ANDROID_PATHS["whatsapp_msgstore"], "msgstore.db")
        wa_path = self._pull_db(ANDROID_PATHS["whatsapp_wa"], "wa.db")

        files = [p for p in [msgstore_path, wa_path] if p]
        if not files:
            return {"messages": [], "contacts": [], "summary": {"messages": 0, "contacts": 0}, "files": []}

        # ---- 解析消息 ----
        if msgstore_path:
            try:
                with SQLiteParser(msgstore_path) as parser:
                    # 构建 jid -> 显示名 映射
                    jid_map = {}
                    if parser.table_exists("jid"):
                        for row in parser.query("SELECT _id, user, display_name, raw_string FROM jid"):
                            jid_map[row["_id"]] = row.get("display_name") or row.get("raw_string") or row.get("user", "")

                    # 解析消息
                    if parser.table_exists("messages"):
                        # 不同版本 WhatsApp 表结构不同，尝试常见字段
                        cols = [c["name"] for c in parser.get_table_schema("messages")]
                        key_remote_jid = "key_remote_jid" if "key_remote_jid" in cols else "chat_row_id"
                        key_from_me = "key_from_me" if "key_from_me" in cols else "from_me"
                        msg_type = "message_type" if "message_type" in cols else "media_wa_type"

                        sql = f"SELECT * FROM messages ORDER BY timestamp DESC"
                        rows = parser.query(sql)
                        for row in rows:
                            remote = row.get(key_remote_jid, "")
                            sender = jid_map.get(remote, str(remote))
                            mtype = row.get(msg_type, 0)
                            messages.append({
                                "id": row.get("_id"),
                                "会话": sender,
                                "方向": "发出" if row.get(key_from_me) else "接收",
                                "类型": WHATSAPP_MSG_TYPES.get(mtype, f"未知({mtype})"),
                                "内容": (row.get("data") or row.get("text_data") or row.get("message") or "")[:500],
                                "日期": timestamp_to_str(row.get("timestamp")),
                                "媒体路径": row.get("media_mime_type", "") or "",
                            })
            except Exception as e:
                from utils.logger import get_logger
                get_logger().warning(f"解析 WhatsApp 消息库失败: {e}")

        # ---- 解析联系人 ----
        if wa_path:
            try:
                with SQLiteParser(wa_path) as parser:
                    if parser.table_exists("wa_contacts"):
                        rows = parser.query("SELECT * FROM wa_contacts ORDER BY display_name")
                        for row in rows:
                            contacts.append({
                                "id": row.get("_id"),
                                "JID": row.get("jid", "") or "",
                                "显示名": row.get("display_name", "") or "",
                                "状态": row.get("status", "") or "",
                                "号码": row.get("number", "") or "",
                            })
            except Exception as e:
                from utils.logger import get_logger
                get_logger().warning(f"解析 WhatsApp 联系人库失败: {e}")

        return {
            "messages": messages,
            "contacts": contacts,
            "summary": {
                "messages": len(messages),
                "contacts": len(contacts),
            },
            "files": files,
        }
