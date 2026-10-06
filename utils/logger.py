# -*- coding: utf-8 -*-
"""日志工具"""

import logging
import sys
from rich.console import Console
from rich.logging import RichHandler

console = Console()


def setup_logger(level: int = logging.INFO) -> logging.Logger:
    """配置并返回日志记录器"""
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=console, rich_tracebacks=True, markup=True)],
    )
    logger = logging.getLogger("root_recovery")
    logger.setLevel(level)
    return logger


def get_logger(name: str = "root_recovery") -> logging.Logger:
    """获取命名日志记录器"""
    logger = logging.getLogger(name)
    if not logger.handlers:
        setup_logger()
    return logger
