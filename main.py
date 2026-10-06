# -*- coding: utf-8 -*-
"""
Android Root 数据还原工具
=========================
基于 Root 权限的 Android 设备数据提取与还原程序。

功能：
  - 通话记录提取与还原
  - 短信/彩信提取与还原
  - 联系人提取与还原
  - 照片/视频提取
  - WhatsApp 消息与联系人提取
  - 系统信息与 WiFi 密码提取
  - 支持 HTML / JSON / CSV 多种导出格式

使用前提：
  - Android 设备已获取 Root 权限
  - 已安装 Android Platform Tools (adb)
  - 设备已开启 USB 调试并授权
"""

import argparse
import sys
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

import config
from adb_utils import ADBManager, ADBError
from extractors.call_logs import CallLogExtractor
from extractors.contacts import ContactsExtractor
from extractors.photos import PhotosExtractor
from extractors.sms import SMSExtractor
from extractors.system_info import SystemInfoExtractor
from extractors.whatsapp import WhatsAppExtractor
from exporters.csv_exporter import CSVExporter
from exporters.html_exporter import HTMLExporter
from exporters.json_exporter import JSONExporter
from utils.helpers import CST
from utils.logger import setup_logger

console = Console()
logger = setup_logger()

# 所有可用提取器
EXTRACTORS = {
    "call_logs": CallLogExtractor,
    "sms": SMSExtractor,
    "contacts": ContactsExtractor,
    "photos": PhotosExtractor,
    "whatsapp": WhatsAppExtractor,
    "system_info": SystemInfoExtractor,
}


def print_banner():
    """打印程序横幅"""
    banner = r"""
    ╔══════════════════════════════════════════════╗
    ║       Android Root 数据还原工具 v1.0         ║
    ║   通话记录 | 短信 | 联系人 | 照片 | WhatsApp ║
    ╚══════════════════════════════════════════════╝
    """
    console.print(f"[bold blue]{banner}[/bold blue]")


def list_available_extractors():
    """列出所有可用提取器"""
    table = Table(title="可用数据类型", show_header=True, header_style="bold magenta")
    table.add_column("标识", style="cyan")
    table.add_column("描述")
    table.add_column("需要Root", justify="center")
    for key, cls in EXTRACTORS.items():
        table.add_row(key, cls.description, "是" if cls.requires_root else "否")
    console.print(table)


def run_extraction(adb: ADBManager, selected: list, output_dir: Path) -> dict:
    """执行选中的提取器"""
    results = {}
    device_info = adb.get_device_info()

    for key in selected:
        if key not in EXTRACTORS:
            logger.warning(f"未知的数据类型: {key}，跳过")
            continue

        cls = EXTRACTORS[key]
        console.print(f"\n[bold cyan]▶ 正在提取: {cls.description}[/bold cyan]")

        extractor = cls(adb, output_dir)
        try:
            result = extractor.extract()
            results[key] = result

            # 显示摘要
            summary = result.get("summary", {})
            if summary:
                parts = [f"{k}: {v}" for k, v in summary.items()]
                console.print(f"  [green]✓ 完成[/green] - {', '.join(parts)}")
            else:
                console.print(f"  [green]✓ 完成[/green]")
        except Exception as e:
            logger.error(f"提取 {cls.description} 时出错: {e}")
            results[key] = {"error": str(e)}

    return results, device_info


def export_results(results: dict, device_info: dict, output_dir: Path, fmt: str):
    """导出结果"""
    export_dir = output_dir / "export"
    export_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(CST).strftime("%Y%m%d_%H%M%S")

    if fmt in ("json", "all"):
        json_path = export_dir / f"recovery_{timestamp}.json"
        JSONExporter.export(results, str(json_path))
        console.print(f"  [green]✓ JSON 报告:[/green] {json_path}")

    if fmt in ("csv", "all"):
        csv_dir = export_dir / "csv"
        files = CSVExporter.export(results, str(csv_dir))
        console.print(f"  [green]✓ CSV 文件:[/green] {len(files)} 个 -> {csv_dir}")

    if fmt in ("html", "all"):
        html_path = export_dir / f"recovery_{timestamp}.html"
        HTMLExporter.export(results, str(html_path), device_info)
        console.print(f"  [green]✓ HTML 报告:[/green] {html_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Android Root 数据还原工具 - 提取并还原通话记录、短信、照片等数据",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  %(prog)s -t call_logs sms contacts        # 提取通话记录、短信、联系人
  %(prog)s -t all -f html                   # 提取全部数据并生成HTML报告
  %(prog)s -t photos -o ./my_backup         # 提取照片到指定目录
  %(prog)s --list                           # 列出所有可提取的数据类型
        """,
    )
    parser.add_argument(
        "-t", "--types", nargs="+",
        help="要提取的数据类型，使用 'all' 提取全部",
        metavar="TYPE",
    )
    parser.add_argument(
        "-f", "--format", default="html",
        choices=config.EXPORT_FORMATS,
        help="导出格式 (默认: html)",
    )
    parser.add_argument(
        "-o", "--output", default=None,
        help="输出目录 (默认: ./output/<时间戳>)",
    )
    parser.add_argument(
        "-s", "--serial", default=None,
        help="指定设备序列号 (多设备时使用)",
    )
    parser.add_argument(
        "--list", action="store_true",
        help="列出所有可提取的数据类型并退出",
    )
    parser.add_argument(
        "--no-root-skip", action="store_true",
        help="即使无 Root 也继续（仅提取无需Root的数据）",
    )

    args = parser.parse_args()

    print_banner()

    if args.list:
        list_available_extractors()
        return

    if not args.types:
        parser.error("请指定要提取的数据类型 (-t)，或使用 --list 查看可用类型")

    # 确定输出目录
    if args.output:
        output_dir = Path(args.output).resolve()
    else:
        timestamp = datetime.now(CST).strftime("%Y%m%d_%H%M%S")
        output_dir = config.OUTPUT_DIR / f"recovery_{timestamp}"
    output_dir.mkdir(parents=True, exist_ok=True)

    # 初始化 ADB
    adb = ADBManager(device_id=args.serial)

    try:
        # 检测设备
        console.print("[bold]正在检测设备...[/bold]")
        devices = adb.list_devices()
        if not devices:
            console.print("[red]✗ 未检测到已连接的 Android 设备[/red]")
            console.print("请确保：")
            console.print("  1. 设备已通过 USB 连接")
            console.print("  2. 已开启 USB 调试")
            console.print("  3. 已在设备上授权此计算机")
            sys.exit(1)

        if len(devices) > 1 and not args.serial:
            console.print(f"[yellow]检测到多个设备: {devices}[/yellow]")
            console.print("请使用 -s <序列号> 指定设备")
            sys.exit(1)

        if not args.serial:
            adb.device_id = devices[0]

        console.print(f"[green]✓ 已连接设备: {adb.device_id}[/green]")

        # 检查 Root
        has_root = adb.check_root()
        if not has_root and not args.no_root_skip:
            console.print("[yellow]⚠ 设备未 Root，将跳过需要 Root 权限的数据类型[/yellow]")

        # 确定要提取的类型
        if "all" in args.types:
            selected = list(EXTRACTORS.keys())
        else:
            selected = args.types

        # 过滤掉需要 root 但无 root 的类型
        if not has_root:
            selected = [t for t in selected if not EXTRACTORS[t].requires_root]
            if not selected:
                console.print("[red]没有可提取的数据类型（所有选中类型都需要 Root）[/red]")
                sys.exit(1)

        console.print(f"\n[bold]将提取以下数据:[/bold] {', '.join(selected)}")
        console.print(f"[bold]输出目录:[/bold] {output_dir}\n")

        # 执行提取
        results, device_info = run_extraction(adb, selected, output_dir)

        # 导出结果
        console.print(f"\n[bold cyan]▶ 正在导出报告 (格式: {args.format})...[/bold cyan]")
        export_results(results, device_info, output_dir, args.format)

        # 完成
        console.print(Panel.fit(
            f"[bold green]数据还原完成！[/bold green]\n"
            f"输出目录: {output_dir}",
            title="完成",
            border_style="green",
        ))

    except ADBError as e:
        console.print(f"[red]✗ ADB 错误: {e}[/red]")
        console.print("[yellow]提示: 请确认已安装 Android Platform Tools 且 adb 在 PATH 中[/yellow]")
        sys.exit(1)
    except KeyboardInterrupt:
        console.print("\n[yellow]用户中断操作[/yellow]")
        sys.exit(130)


if __name__ == "__main__":
    main()
