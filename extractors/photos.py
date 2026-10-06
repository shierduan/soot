# -*- coding: utf-8 -*-
"""
照片/媒体提取器
从设备的公开存储目录拉取照片、视频等媒体文件。
通常不需要 Root 权限。
"""

import os
from typing import Any, Dict, List

from config import MEDIA_PATHS
from extractors.base import BaseExtractor
from utils.helpers import human_readable_size

# 常见图片和视频扩展名
IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".heic", ".dng"}
VIDEO_EXTS = {".mp4", ".3gp", ".avi", ".mov", ".mkv", ".flv", ".wmv"}


class PhotosExtractor(BaseExtractor):
    name = "photos"
    description = "照片与视频"
    requires_root = False  # 通常在 sdcard 上，无需 root

    def extract(self) -> Dict[str, Any]:
        files_info: List[Dict[str, Any]] = []
        total_count = 0
        total_size = 0

        # 尝试拉取各个媒体目录
        for label, remote_dir in MEDIA_PATHS.items():
            local_subdir = label
            count = self._pull_dir(remote_dir, local_subdir)
            if count > 0:
                total_count += count
                # 统计本地文件信息
                local_path = self.output_dir / local_subdir
                if local_path.exists():
                    for root, _, files in os.walk(local_path):
                        for f in files:
                            fp = os.path.join(root, f)
                            ext = os.path.splitext(f)[1].lower()
                            try:
                                size = os.path.getsize(fp)
                            except OSError:
                                size = 0
                            total_size += size
                            file_type = "图片" if ext in IMAGE_EXTS else (
                                "视频" if ext in VIDEO_EXTS else "其他"
                            )
                            files_info.append({
                                "文件名": f,
                                "类型": file_type,
                                "大小": human_readable_size(size),
                                "路径": os.path.relpath(fp, self.output_dir),
                            })

        return {
            "records": files_info,
            "summary": {
                "total_files": total_count,
                "total_size": human_readable_size(total_size),
                "images": sum(1 for f in files_info if f["类型"] == "图片"),
                "videos": sum(1 for f in files_info if f["类型"] == "视频"),
            },
            "files": [],
        }
