# -*- coding: utf-8 -*-
"""
联系人提取器
数据库路径: /data/data/com.android.providers.contacts/databases/contacts2.db
"""

from typing import Any, Dict, List

from config import ANDROID_PATHS
from extractors.base import BaseExtractor
from parsers.sqlite_parser import SQLiteParser


class ContactsExtractor(BaseExtractor):
    name = "contacts"
    description = "联系人"
    requires_root = True

    def extract(self) -> Dict[str, Any]:
        records: List[Dict[str, Any]] = []
        db_path = self._pull_db(ANDROID_PATHS["contacts"], "contacts2.db")

        if not db_path:
            return {"records": [], "summary": {"total": 0}, "files": []}

        try:
            with SQLiteParser(db_path) as parser:
                if not parser.table_exists("data"):
                    return {"records": [], "summary": {"total": 0}, "files": [db_path]}

                # 联系人数据：raw_contacts + data 表
                # data.mimetype_id 对应 mimetypes 表
                # 常见 mimetype:
                #   vnd.android.cursor.item/name          -> 姓名
                #   vnd.android.cursor.item/phone_v2      -> 电话
                #   vnd.android.cursor.item/email_v2      -> 邮箱

                # 获取 mimetype id 映射
                mime_map = {}
                if parser.table_exists("mimetypes"):
                    for row in parser.query("SELECT _id, mimetype FROM mimetypes"):
                        mime_map[row["_id"]] = row["mimetype"]

                # 读取所有 data 记录
                data_rows = parser.query(
                    "SELECT raw_contact_id, mimetype_id, data1, data2, data3, data4 "
                    "FROM data WHERE deleted = 0 ORDER BY raw_contact_id"
                )

                # 按 raw_contact_id 聚合
                contacts: Dict[int, Dict[str, Any]] = {}
                for row in data_rows:
                    rid = row["raw_contact_id"]
                    if rid not in contacts:
                        contacts[rid] = {
                            "id": rid,
                            "姓名": "",
                            "电话": [],
                            "邮箱": [],
                            "组织": "",
                            "备注": "",
                        }
                    mime = mime_map.get(row["mimetype_id"], "")
                    data1 = row.get("data1") or ""

                    if "name" in mime:
                        # data1 = display_name, data2 = given, data3 = family
                        contacts[rid]["姓名"] = data1
                    elif "phone" in mime:
                        if data1:
                            contacts[rid]["电话"].append(data1)
                    elif "email" in mime:
                        if data1:
                            contacts[rid]["邮箱"].append(data1)
                    elif "organization" in mime:
                        contacts[rid]["组织"] = data1
                    elif "note" in mime:
                        contacts[rid]["备注"] = data1

                # 转换为列表
                for rid, c in sorted(contacts.items()):
                    if c["姓名"] or c["电话"]:
                        records.append({
                            "id": c["id"],
                            "姓名": c["姓名"] or "(未命名)",
                            "电话": "; ".join(c["电话"]),
                            "邮箱": "; ".join(c["邮箱"]),
                            "组织": c["组织"],
                            "备注": c["备注"],
                        })
        except Exception as e:
            from utils.logger import get_logger
            get_logger().warning(f"解析联系人数据库失败: {e}")

        return {
            "records": records,
            "summary": {"total": len(records)},
            "files": [db_path],
        }
