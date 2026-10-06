# Android Root 数据还原工具

基于 Root 权限的 Android 设备数据提取与还原程序。通过 ADB 连接已 Root 的 Android 设备，读取受保护的系统数据库和媒体文件，将通话记录、短信、联系人、照片、WhatsApp 消息等数据提取并还原为可视化报告。

## 功能特性

| 数据类型 | 说明 | 需要 Root |
|---------|------|:---------:|
| 通话记录 | 来电/去电/未接记录，含号码、姓名、时长 | ✓ |
| 短信/彩信 | 收件箱、已发送、草稿等短信与彩信 | ✓ |
| 联系人 | 姓名、电话、邮箱、组织、备注 | ✓ |
| 照片/视频 | DCIM、Pictures、Movies 等目录媒体文件 | ✗ |
| WhatsApp | 消息记录与联系人 | ✓ |
| 系统信息 | 设备信息、WiFi 网络与密码 | ✓ |

## 环境要求

- Python 3.8+
- Android Platform Tools（`adb`）
- 已 Root 的 Android 设备，并开启 USB 调试

## 安装

```bash
# 安装 Python 依赖
pip install -r requirements.txt

# 确认 adb 可用
adb version
```

## 快速开始

```bash
# 1. 查看所有可提取的数据类型
python3 main.py --list

# 2. 提取通话记录、短信和联系人，生成 HTML 报告
python3 main.py -t call_logs sms contacts

# 3. 提取全部数据，导出所有格式
python3 main.py -t all -f all

# 4. 仅提取照片（无需 Root）
python3 main.py -t photos -o ./photo_backup

# 5. 指定设备序列号（多设备时）
python3 main.py -t all -s <设备序列号>
```

## 命令行参数

```
-t, --types TYPE [TYPE ...]   要提取的数据类型，使用 'all' 提取全部
-f, --format FORMAT           导出格式: html / json / csv / all (默认: html)
-o, --output OUTPUT           输出目录 (默认: ./output/<时间戳>)
-s, --serial SERIAL           指定设备序列号
--list                        列出所有可提取的数据类型
--no-root-skip                无 Root 时也继续（仅提取无需 Root 的数据）
```

## 工作原理

1. **设备连接**：通过 ADB 检测并连接 Android 设备
2. **Root 检测**：验证 `su` 权限是否可用
3. **数据拉取**：
   - 受保护数据库（需 Root）：使用 `su -c cp` 将文件复制到 `/sdcard` 临时目录，再 `adb pull`
   - 媒体文件：直接 `adb pull` 公开存储目录
4. **数据解析**：使用 Python `sqlite3` 解析 Android 系统数据库
5. **报告生成**：导出为 HTML 可视化报告、JSON 或 CSV 文件

## 数据来源路径

```
通话记录: /data/data/com.android.providers.contacts/databases/calllog.db
短信彩信: /data/data/com.android.providers.telephony/databases/mmssms.db
联系人:   /data/data/com.android.providers.contacts/databases/contacts2.db
WiFi:     /data/misc/wifi/WifiConfigStore.xml
WhatsApp: /data/data/com.whatsapp/databases/msgstore.db, wa.db
照片:     /sdcard/DCIM/, /sdcard/Pictures/, /sdcard/Movies/
```

## 项目结构

```
.
├── main.py                 # 主 CLI 入口
├── config.py               # 全局配置（路径、表名等）
├── adb_utils.py            # ADB + Root 通信封装
├── requirements.txt        # Python 依赖
├── parsers/
│   └── sqlite_parser.py    # SQLite 数据库解析器
├── extractors/
│   ├── base.py             # 提取器基类
│   ├── call_logs.py        # 通话记录提取
│   ├── sms.py              # 短信/彩信提取
│   ├── contacts.py         # 联系人提取
│   ├── photos.py           # 照片/视频提取
│   ├── whatsapp.py         # WhatsApp 提取
│   └── system_info.py      # 系统信息/WiFi 提取
├── exporters/
│   ├── html_exporter.py    # HTML 报告生成
│   ├── json_exporter.py    # JSON 导出
│   └── csv_exporter.py     # CSV 导出
└── utils/
    ├── helpers.py          # 通用工具函数
    └── logger.py           # 日志工具
```

## 输出示例

运行后将在输出目录生成：

```
output/recovery_20240101_120000/
├── call_logs/
│   └── raw/calllog.db
├── sms/
│   └── raw/mmssms.db
├── contacts/
├── photos/
├── whatsapp/
└── export/
    ├── recovery_20240101_120000.html    # 可视化报告
    ├── recovery_20240101_120000.json    # 结构化数据
    └── csv/                             # 各数据表 CSV
        ├── call_logs_records.csv
        ├── sms_sms.csv
        └── ...
```

## 免责声明

本工具仅供合法的数据备份、取证分析和个人设备的数据恢复使用。使用本工具访问他人设备数据可能违反相关法律法规，请确保你拥有设备的合法访问权限。
