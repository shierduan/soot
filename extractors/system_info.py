# -*- coding: utf-8 -*-
"""
系统信息提取器
提取设备基本信息、WiFi 配置等。
"""

import xml.etree.ElementTree as ET
from typing import Any, Dict, List

from config import ANDROID_PATHS
from extractors.base import BaseExtractor


class SystemInfoExtractor(BaseExtractor):
    name = "system_info"
    description = "系统信息与WiFi"
    requires_root = True

    def extract(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "device_info": {},
            "wifi_networks": [],
            "files": [],
        }

        # 设备信息
        result["device_info"] = self.adb.get_device_info()

        # WiFi 配置
        wifi_content = None
        try:
            wifi_content = self.adb.root_read_file(ANDROID_PATHS["wifi"])
        except Exception:
            pass

        if wifi_content:
            # 保存原始文件
            raw_path = self.raw_dir / "WifiConfigStore.xml"
            raw_path.write_text(wifi_content, encoding="utf-8", errors="ignore")
            result["files"].append(str(raw_path))

            # 解析 WiFi 网络
            result["wifi_networks"] = self._parse_wifi_xml(wifi_content)

        return result

    def _parse_wifi_xml(self, content: str) -> List[Dict[str, Any]]:
        """解析 WiFi 配置 XML"""
        networks: List[Dict[str, Any]] = []
        try:
            root = ET.fromstring(content)
            # Android 10+ 格式
            for network in root.iter("WifiConfiguration"):
                ssid = ""
                psk = ""
                for string_elem in network.iter("string"):
                    name = string_elem.get("name", "")
                    if name == "SSID":
                        ssid = string_elem.text or ""
                    elif name == "PreSharedKey":
                        psk = string_elem.text or ""
                if ssid:
                    networks.append({
                        "SSID": ssid.strip('"'),
                        "密码": psk.strip('"'),
                        "加密": "WPA/WPA2" if psk else "开放",
                    })
        except ET.ParseError as e:
            from utils.logger import get_logger
            get_logger().warning(f"解析 WiFi XML 失败: {e}")
        return networks
