# -*- coding: utf-8 -*-
"""
提取器基类
所有数据提取器都继承自此基类。
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List

from adb_utils import ADBManager
from utils.logger import get_logger

logger = get_logger("extractor")


class BaseExtractor(ABC):
    """数据提取器基类"""

    # 提取器名称（用于显示和输出目录）
    name: str = "base"
    # 描述
    description: str = ""
    # 是否需要 Root 权限
    requires_root: bool = True

    def __init__(self, adb: ADBManager, output_dir: Path):
        self.adb = adb
        self.output_dir = Path(output_dir) / self.name
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.raw_dir = self.output_dir / "raw"
        self.raw_dir.mkdir(parents=True, exist_ok=True)

    @abstractmethod
    def extract(self) -> Dict[str, Any]:
        """
        执行数据提取。
        返回包含提取结果的字典，通常包含：
        - records: 记录列表
        - summary: 摘要信息
        - files: 提取的原始文件路径
        """
        pass

    def _pull_db(self, remote_path: str, local_name: str) -> str:
        """拉取数据库文件到 raw 目录"""
        local_path = self.raw_dir / local_name
        success = self.adb.pull_file(remote_path, str(local_path), use_root=self.requires_root)
        if success:
            logger.info(f"[green]✓ 已拉取[/green] {local_name}")
            return str(local_path)
        else:
            logger.warning(f"[yellow]✗ 拉取失败[/yellow] {remote_path}")
            return ""

    def _pull_dir(self, remote_dir: str, local_subdir: str) -> int:
        """拉取目录到输出目录"""
        local_path = self.output_dir / local_subdir
        return self.adb.pull_directory(remote_dir, str(local_path), use_root=self.requires_root)
