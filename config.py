# -*- coding: utf-8 -*-
"""
Android Root 数据还原工具 - 全局配置
"""

import os
from pathlib import Path

# ========== 项目路径 ==========
BASE_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = BASE_DIR / "output"
TEMPLATES_DIR = BASE_DIR / "templates"
TEMP_DIR = BASE_DIR / ".temp"

# ========== Android 系统数据路径（需 Root 访问） ==========
# 这些路径在已 Root 的 Android 设备上需要 root 权限才能读取
ANDROID_PATHS = {
    # 通话记录数据库
    "call_log": "/data/data/com.android.providers.contacts/databases/calllog.db",
    # 短信/彩信数据库
    "sms_mms": "/data/data/com.android.providers.telephony/databases/mmssms.db",
    # 联系人数据库
    "contacts": "/data/data/com.android.providers.contacts/databases/contacts2.db",
    # WiFi 配置
    "wifi": "/data/misc/wifi/WifiConfigStore.xml",
    # WhatsApp 消息数据库
    "whatsapp_msgstore": "/data/data/com.whatsapp/databases/msgstore.db",
    # WhatsApp 联系人数据库
    "whatsapp_wa": "/data/data/com.whatsapp/databases/wa.db",
    # 微信数据目录
    "wechat": "/data/data/com.tencent.mm/MicroMsg/",
}

# ========== 媒体文件路径（通常无需 Root） ==========
MEDIA_PATHS = {
    "dcim": "/sdcard/DCIM/",
    "pictures": "/sdcard/Pictures/",
    "movies": "/sdcard/Movies/",
    "downloads": "/sdcard/Download/",
    "whatsapp_media": "/sdcard/Android/media/com.whatsapp/WhatsApp/Media/",
    "wechat_media": "/sdcard/Android/data/com.tencent.mm/MicroMsg/",
}

# ========== 导出选项 ==========
EXPORT_FORMATS = ["html", "json", "csv", "all"]
DEFAULT_EXPORT_FORMAT = "html"

# ========== ADB 配置 ==========
ADB_DEFAULT_TIMEOUT = 30
ADB_PULL_TIMEOUT = 600  # 拉取大文件（如照片目录）超时

# ========== 数据库表名映射 ==========
DB_TABLES = {
    "call_log": ["calls"],
    "sms_mms": ["sms", "mms", "threads"],
    "contacts": [
        "contacts", "raw_contacts", "data", "phones",
        "emails", "structured_name", "phone_lookup"
    ],
    "whatsapp_msgstore": ["messages", "chat_list", "media_refs", "jid"],
    "whatsapp_wa": ["wa_contacts", "jid"],
}


def ensure_dirs():
    """确保所有需要的目录存在"""
    for d in [OUTPUT_DIR, TEMP_DIR]:
        d.mkdir(parents=True, exist_ok=True)
