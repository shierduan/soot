# -*- coding: utf-8 -*-
"""
ADB 工具模块
负责与已 Root 的 Android 设备通信，拉取受保护的数据文件。

核心策略：
1. 检测设备连接状态
2. 检查 Root 权限（su）
3. 将受保护的数据库文件复制到临时可读路径后拉取
4. 拉取媒体文件目录
"""

import os
import shlex
import subprocess
import time
from pathlib import Path
from typing import List, Optional, Tuple

from config import ADB_DEFAULT_TIMEOUT, ADB_PULL_TIMEOUT, TEMP_DIR
from utils.logger import get_logger

logger = get_logger("adb")


class ADBError(Exception):
    """ADB 操作异常"""
    pass


class ADBManager:
    """ADB 管理器：封装与 Android 设备的 Root 通信"""

    def __init__(self, device_id: Optional[str] = None, adb_path: str = "adb"):
        self.device_id = device_id
        self.adb_path = adb_path
        self._has_root = None

    # ---------- 基础命令执行 ----------
    def _build_cmd(self, args: List[str]) -> List[str]:
        """构建带设备 ID 的 ADB 命令"""
        cmd = [self.adb_path]
        if self.device_id:
            cmd += ["-s", self.device_id]
        cmd += args
        return cmd

    def run(self, args: List[str], timeout: int = ADB_DEFAULT_TIMEOUT,
            check: bool = True, capture: bool = True) -> subprocess.CompletedProcess:
        """执行 ADB 命令"""
        cmd = self._build_cmd(args)
        logger.debug(f"执行命令: {' '.join(shlex.quote(c) for c in cmd)}")
        try:
            result = subprocess.run(
                cmd,
                capture_output=capture,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            raise ADBError(f"命令超时 ({timeout}s): {' '.join(cmd)}")
        except FileNotFoundError:
            raise ADBError(f"未找到 adb 命令，请确保已安装 Android Platform Tools")

        if check and result.returncode != 0:
            stderr = result.stderr.strip()
            raise ADBError(f"命令失败 (exit={result.returncode}): {stderr}")
        return result

    def shell(self, command: str, **kwargs) -> subprocess.CompletedProcess:
        """在设备上执行 shell 命令"""
        return self.run(["shell", command], **kwargs)

    # ---------- 设备检测 ----------
    def list_devices(self) -> List[str]:
        """列出已连接的设备序列号"""
        result = self.run(["devices"], check=False)
        devices = []
        for line in result.stdout.strip().splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 2 and parts[1] == "device":
                devices.append(parts[0])
        return devices

    def wait_for_device(self, timeout: int = 60) -> bool:
        """等待设备连接"""
        try:
            self.run(["wait-for-device"], timeout=timeout)
            return True
        except ADBError:
            return False

    def get_device_info(self) -> dict:
        """获取设备基本信息"""
        info = {}
        props = ["ro.product.model", "ro.product.brand", "ro.build.version.release",
                 "ro.build.version.sdk", "ro.product.cpu.abi"]
        for prop in props:
            try:
                r = self.shell(f"getprop {prop}", check=False)
                info[prop] = r.stdout.strip()
            except ADBError:
                info[prop] = ""
        return info

    # ---------- Root 检测 ----------
    def check_root(self) -> bool:
        """检测设备是否具有 Root 权限"""
        if self._has_root is not None:
            return self._has_root
        try:
            # 尝试使用 su 获取 id
            result = self.shell("su -c id", check=False, timeout=10)
            if result.returncode == 0 and "uid=0" in result.stdout:
                self._has_root = True
                logger.info("[green]✓ 设备已获取 Root 权限[/green]")
                return True
        except ADBError:
            pass

        # 备用：检查 su 二进制是否存在
        try:
            result = self.shell("which su", check=False, timeout=10)
            if result.returncode == 0 and result.stdout.strip():
                self._has_root = True
                logger.info("[green]✓ 检测到 su 二进制[/green]")
                return True
        except ADBError:
            pass

        self._has_root = False
        logger.warning("[yellow]✗ 设备未获取 Root 权限，部分数据无法提取[/yellow]")
        return False

    # ---------- 文件操作（Root） ----------
    def root_read_file(self, remote_path: str) -> str:
        """以 Root 权限读取设备上文件的内容（文本）"""
        result = self.shell(f"su -c 'cat {shlex.quote(remote_path)}'", check=False)
        if result.returncode != 0:
            raise ADBError(f"无法读取文件: {remote_path} - {result.stderr.strip()}")
        return result.stdout

    def root_file_exists(self, remote_path: str) -> bool:
        """检查设备上文件是否存在（Root 权限）"""
        result = self.shell(f"su -c 'test -e {shlex.quote(remote_path)} && echo exists'", check=False)
        return result.returncode == 0 and "exists" in result.stdout

    def root_copy_to_temp(self, remote_path: str, temp_dest: Optional[str] = None) -> str:
        """
        将受保护的文件复制到设备临时目录以供 adb pull。
        返回设备上的临时路径。
        """
        if temp_dest is None:
            basename = os.path.basename(remote_path.rstrip("/"))
            temp_dest = f"/sdcard/.recover_temp_{basename}"

        # 先删除旧的临时文件
        self.shell(f"rm -f {shlex.quote(temp_dest)}", check=False)

        # 使用 su 复制到可读位置
        result = self.shell(
            f"su -c 'cp {shlex.quote(remote_path)} {shlex.quote(temp_dest)} && "
            f"chmod 644 {shlex.quote(temp_dest)}'",
            check=False
        )
        if result.returncode != 0:
            # 备用方案：使用 cat 重定向
            result = self.shell(
                f"su -c 'cat {shlex.quote(remote_path)} > {shlex.quote(temp_dest)}'",
                check=False
            )
            if result.returncode != 0:
                raise ADBError(f"无法复制文件到临时目录: {remote_path}\n{result.stderr}")
            self.shell(f"chmod 644 {shlex.quote(temp_dest)}", check=False)

        return temp_dest

    def pull_file(self, remote_path: str, local_path: str, use_root: bool = True) -> bool:
        """
        从设备拉取文件到本地。
        对于受保护路径，先复制到临时目录再 pull。
        """
        local_path = str(Path(local_path).resolve())
        os.makedirs(os.path.dirname(local_path), exist_ok=True)

        try:
            if use_root and self.check_root():
                # 先检查源文件是否存在
                if not self.root_file_exists(remote_path):
                    logger.debug(f"文件不存在: {remote_path}")
                    return False

                # 复制到临时路径
                temp_path = self.root_copy_to_temp(remote_path)
                try:
                    # 拉取临时文件
                    result = self.run(["pull", temp_path, local_path],
                                      timeout=ADB_PULL_TIMEOUT, check=False)
                    if result.returncode != 0:
                        raise ADBError(result.stderr.strip())
                finally:
                    # 清理临时文件
                    self.shell(f"rm -f {shlex.quote(temp_path)}", check=False)
            else:
                # 非 Root：直接 pull（适用于 sdcard 等公开路径）
                result = self.run(["pull", remote_path, local_path],
                                  timeout=ADB_PULL_TIMEOUT, check=False)
                if result.returncode != 0:
                    logger.debug(f"拉取失败（可能文件不存在）: {remote_path}")
                    return False

            if os.path.exists(local_path) and os.path.getsize(local_path) > 0:
                return True
            else:
                # 清理空文件
                if os.path.exists(local_path):
                    os.remove(local_path)
                return False
        except ADBError as e:
            logger.warning(f"拉取文件失败 {remote_path}: {e}")
            return False

    def pull_directory(self, remote_dir: str, local_dir: str, use_root: bool = False) -> int:
        """
        拉取整个目录到本地。
        返回成功拉取的文件数量。
        """
        local_dir = str(Path(local_dir).resolve())
        os.makedirs(local_dir, exist_ok=True)

        # 列出远程目录中的文件
        try:
            if use_root and self.check_root():
                result = self.shell(f"su -c 'find {shlex.quote(remote_dir)} -type f 2>/dev/null'",
                                    check=False)
            else:
                result = self.shell(f"find {shlex.quote(remote_dir)} -type f 2>/dev/null",
                                    check=False)
        except ADBError:
            return 0

        remote_files = [f.strip() for f in result.stdout.strip().splitlines() if f.strip()]
        if not remote_files:
            logger.debug(f"目录为空或不存在: {remote_dir}")
            return 0

        count = 0
        for remote_file in remote_files:
            # 计算本地相对路径
            rel_path = os.path.relpath(remote_file, remote_dir)
            local_file = os.path.join(local_dir, rel_path)
            if self.pull_file(remote_file, local_file, use_root=use_root):
                count += 1

        return count

    # ---------- 数据库完整性辅助 ----------
    def get_file_size(self, remote_path: str) -> int:
        """获取远程文件大小（字节）"""
        try:
            result = self.shell(f"su -c 'stat -c %s {shlex.quote(remote_path)}'", check=False)
            if result.returncode == 0:
                return int(result.stdout.strip())
        except (ADBError, ValueError):
            pass
        return -1
