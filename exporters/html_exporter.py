# -*- coding: utf-8 -*-
"""
HTML 报告导出器
生成可视化的 HTML 数据报告。
"""

import html
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from config import TEMPLATES_DIR
from utils.helpers import CST
from utils.logger import get_logger

logger = get_logger("exporter")


class HTMLExporter:
    """HTML 报告导出器"""

    @staticmethod
    def export(data: Dict[str, Any], output_path: str, device_info: Dict[str, str] = None) -> str:
        """生成 HTML 报告"""
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)

        # 构建报告 HTML
        report = HTMLReport(device_info or {})
        report.add_section_data(data)
        html_content = report.render()

        with open(output, "w", encoding="utf-8") as f:
            f.write(html_content)

        return str(output)


class HTMLReport:
    """HTML 报告构建器"""

    def __init__(self, device_info: Dict[str, str]):
        self.device_info = device_info
        self.sections: List[str] = []
        self.summary_cards: List[Dict[str, str]] = []

    def add_section_data(self, data: Dict[str, Any]):
        """从提取数据构建报告内容"""
        for category, content in data.items():
            if not isinstance(content, dict):
                continue
            self._add_category_section(category, content)

    def _add_category_section(self, category: str, content: Dict[str, Any]):
        """添加一个数据分类的报告区块"""
        titles = {
            "call_logs": "通话记录",
            "sms": "短信与彩信",
            "contacts": "联系人",
            "photos": "照片与视频",
            "whatsapp": "WhatsApp",
            "system_info": "系统信息",
        }
        title = titles.get(category, category)

        # 摘要信息
        summary = content.get("summary", {})
        if summary:
            for k, v in summary.items():
                if isinstance(v, int) and v > 0:
                    self.summary_cards.append({
                        "label": f"{title} - {k}",
                        "value": str(v),
                    })

        section_html = f'<div class="category"><h2>{html.escape(title)}</h2>'

        # 处理不同数据结构
        if category == "sms":
            section_html += self._render_table(content.get("sms", []), "短信")
            section_html += self._render_table(content.get("mms", []), "彩信")
        elif category == "whatsapp":
            section_html += self._render_table(content.get("messages", []), "消息")
            section_html += self._render_table(content.get("contacts", []), "联系人")
        elif category == "system_info":
            # 设备信息
            dev_info = content.get("device_info", {})
            if dev_info:
                section_html += "<h3>设备信息</h3>"
                section_html += self._render_kv_table(dev_info)
            wifi = content.get("wifi_networks", [])
            if wifi:
                section_html += "<h3>WiFi 网络</h3>"
                section_html += self._render_table(wifi, "WiFi")
        elif category == "photos":
            records = content.get("records", [])
            if records:
                section_html += self._render_table(records[:200], "媒体文件 (前200条)")
        else:
            records = content.get("records", [])
            if records:
                section_html += self._render_table(records, title)

        section_html += "</div>"
        self.sections.append(section_html)

    def _render_table(self, records: List[Dict[str, Any]], title: str) -> str:
        """渲染数据表格"""
        if not records:
            return f'<p class="empty">暂无{title}数据</p>'

        # 限制展示条数
        display = records[:500]
        if len(records) > 500:
            note = f'<p class="note">共 {len(records)} 条，仅显示前 500 条</p>'
        else:
            note = ""

        fieldnames = list(records[0].keys())
        header = "".join(f"<th>{html.escape(str(f))}</th>" for f in fieldnames)

        rows = []
        for rec in display:
            cells = "".join(
                f"<td>{html.escape(str(rec.get(f, '')))}</td>" for f in fieldnames
            )
            rows.append(f"<tr>{cells}</tr>")

        return f"""
        <h3>{html.escape(title)} ({len(records)} 条)</h3>
        {note}
        <div class="table-wrapper">
        <table>
            <thead><tr>{header}</tr></thead>
            <tbody>{''.join(rows)}</tbody>
        </table>
        </div>
        """

    def _render_kv_table(self, data: Dict[str, Any]) -> str:
        """渲染键值对表格"""
        rows = "".join(
            f"<tr><td>{html.escape(str(k))}</td><td>{html.escape(str(v))}</td></tr>"
            for k, v in data.items()
        )
        return f"""
        <div class="table-wrapper">
        <table>
            <thead><tr><th>属性</th><th>值</th></tr></thead>
            <tbody>{rows}</tbody>
        </table>
        </div>
        """

    def render(self) -> str:
        """渲染完整 HTML"""
        now = datetime.now(CST).strftime("%Y-%m-%d %H:%M:%S")
        summary_html = "".join(
            f'<div class="stat-card"><div class="stat-value">{html.escape(c["value"])}</div>'
            f'<div class="stat-label">{html.escape(c["label"])}</div></div>'
            for c in self.summary_cards
        )

        device_lines = "".join(
            f"<li>{html.escape(str(k))}: <strong>{html.escape(str(v))}</strong></li>"
            for k, v in self.device_info.items()
        )

        return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Android 数据还原报告</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: -apple-system, "Segoe UI", "Microsoft YaHei", sans-serif; background: #f5f7fa; color: #333; line-height: 1.6; }}
.container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
header {{ background: linear-gradient(135deg, #1e3c72, #2a5298); color: #fff; padding: 30px; border-radius: 12px; margin-bottom: 24px; }}
header h1 {{ font-size: 28px; margin-bottom: 8px; }}
header p {{ opacity: 0.9; }}
.device-info {{ background: #fff; padding: 16px 20px; border-radius: 8px; margin-bottom: 24px; box-shadow: 0 2px 8px rgba(0,0,0,0.06); }}
.device-info ul {{ list-style: none; columns: 2; }}
.device-info li {{ padding: 4px 0; }}
.stats {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: 16px; margin-bottom: 24px; }}
.stat-card {{ background: #fff; padding: 20px; border-radius: 8px; text-align: center; box-shadow: 0 2px 8px rgba(0,0,0,0.06); border-top: 3px solid #2a5298; }}
.stat-value {{ font-size: 32px; font-weight: bold; color: #2a5298; }}
.stat-label {{ font-size: 13px; color: #666; margin-top: 4px; }}
.category {{ background: #fff; padding: 24px; border-radius: 8px; margin-bottom: 24px; box-shadow: 0 2px 8px rgba(0,0,0,0.06); }}
.category h2 {{ color: #1e3c72; border-bottom: 2px solid #eee; padding-bottom: 10px; margin-bottom: 16px; }}
.category h3 {{ color: #555; margin: 16px 0 10px; }}
.table-wrapper {{ overflow-x: auto; }}
table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
th {{ background: #f0f4f8; padding: 10px; text-align: left; position: sticky; top: 0; }}
td {{ padding: 8px 10px; border-bottom: 1px solid #eee; max-width: 400px; word-break: break-all; }}
tr:hover {{ background: #f9fafb; }}
.empty {{ color: #999; padding: 12px 0; }}
.note {{ color: #888; font-size: 12px; margin: 4px 0; }}
footer {{ text-align: center; color: #999; padding: 20px; font-size: 12px; }}
</style>
</head>
<body>
<div class="container">
    <header>
        <h1>Android 数据还原报告</h1>
        <p>生成时间: {now}</p>
    </header>
    <div class="device-info">
        <strong>设备信息</strong>
        <ul>{device_lines}</ul>
    </div>
    <div class="stats">{summary_html}</div>
    {''.join(self.sections)}
    <footer>Android Root 数据还原工具 - 本报告仅供取证参考</footer>
</div>
</body>
</html>"""
