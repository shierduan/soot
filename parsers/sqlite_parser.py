# -*- coding: utf-8 -*-
"""
SQLite 数据库解析器
负责读取 Android 数据库文件并提取结构化数据。
"""

import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional

from utils.logger import get_logger

logger = get_logger("parser")


class SQLiteParser:
    """SQLite 数据库解析器"""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self.conn: Optional[sqlite3.Connection] = None

    def open(self):
        """打开数据库连接"""
        if not Path(self.db_path).exists():
            raise FileNotFoundError(f"数据库文件不存在: {self.db_path}")
        try:
            self.conn = sqlite3.connect(self.db_path)
            self.conn.row_factory = sqlite3.Row
        except sqlite3.Error as e:
            raise RuntimeError(f"无法打开数据库 {self.db_path}: {e}")

    def close(self):
        """关闭数据库连接"""
        if self.conn:
            self.conn.close()
            self.conn = None

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *args):
        self.close()

    def list_tables(self) -> List[str]:
        """列出数据库中所有表"""
        if not self.conn:
            self.open()
        try:
            cursor = self.conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            )
            return [row[0] for row in cursor.fetchall()]
        except sqlite3.Error as e:
            logger.warning(f"列出表失败: {e}")
            return []

    def get_table_schema(self, table: str) -> List[Dict[str, str]]:
        """获取表结构"""
        if not self.conn:
            self.open()
        try:
            cursor = self.conn.execute(f"PRAGMA table_info({table})")
            schema = []
            for row in cursor.fetchall():
                schema.append({
                    "cid": row[0],
                    "name": row[1],
                    "type": row[2],
                    "notnull": row[3],
                    "dflt_value": row[4],
                    "pk": row[5],
                })
            return schema
        except sqlite3.Error as e:
            logger.warning(f"获取表结构失败 ({table}): {e}")
            return []

    def query(self, sql: str, params: tuple = ()) -> List[Dict[str, Any]]:
        """执行查询并返回字典列表"""
        if not self.conn:
            self.open()
        try:
            cursor = self.conn.execute(sql, params)
            columns = [desc[0] for desc in cursor.description]
            rows = []
            for row in cursor.fetchall():
                rows.append(dict(zip(columns, row)))
            return rows
        except sqlite3.Error as e:
            logger.warning(f"查询失败: {e}\nSQL: {sql}")
            return []

    def get_row_count(self, table: str) -> int:
        """获取表行数"""
        if not self.conn:
            self.open()
        try:
            cursor = self.conn.execute(f"SELECT COUNT(*) FROM {table}")
            return cursor.fetchone()[0]
        except sqlite3.Error:
            return 0

    def table_exists(self, table: str) -> bool:
        """检查表是否存在"""
        return table in self.list_tables()
