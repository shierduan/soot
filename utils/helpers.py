# -*- coding: utf-8 -*-
"""通用工具函数"""

import hashlib
import os
from datetime import datetime, timezone, timedelta
from pathlib import Path

# 中国时区
CST = timezone(timedelta(hours=8))


def timestamp_to_str(ts_ms) -> str:
    """将毫秒时间戳转换为可读字符串"""
    if ts_ms is None:
        return ""
    try:
        ts = int(ts_ms)
        # Android 时间戳通常是毫秒
        if ts > 1e12:
            ts = ts / 1000.0
        dt = datetime.fromtimestamp(ts, tz=CST)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, OSError, OverflowError):
        return str(ts_ms)


def file_md5(filepath: str) -> str:
    """计算文件 MD5"""
    h = hashlib.md5()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def safe_filename(name: str) -> str:
    """生成安全的文件名"""
    invalid = '<>:"/\\|?*'
    for ch in invalid:
        name = name.replace(ch, "_")
    return name.strip()


def human_readable_size(size_bytes: int) -> str:
    """将字节数转换为可读大小"""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"
