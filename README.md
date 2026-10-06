# 数据还原大师 (DataRecovery)

一款基于 **Root 权限** 的 Android 原生数据恢复与安全删除工具。

## 核心定位

本工具不是简单的数据导出工具，而是**数据恢复工具**——针对**已被删除、但数据分区中仍残留原始数据**的场景，通过直接扫描存储分区和解析 SQLite 数据库的空闲空间，将已删除的数据还原出来。

## 功能特性

### 数据恢复
| 数据类型 | 恢复方式 | 支持预览 |
|---------|---------|:-------:|
| 图片 (JPEG/PNG/GIF/WebP/BMP/HEIC) | 文件雕刻 (File Carving) | ✓ |
| 视频 (MP4/3GP/MKV/AVI/FLV) | 文件雕刻 (File Carving) | ✓ |
| 音频 (MP3/WAV/AAC/AMR) | 文件雕刻 (File Carving) | ✓ |
| 通话记录 | SQLite 已删除记录恢复 | ✓ |
| 短信/彩信 | SQLite 已删除记录恢复 | ✓ |
| 联系人 | SQLite 已删除记录恢复 | ✓ |
| 文档/压缩包 | 文件雕刻 (File Carving) | ✓ |

### 安全删除
- **锁屏密码验证**：删除前必须通过系统锁屏验证（PIN/图案/密码/生物识别）
- **数据覆写**：可选 1-7 次覆写（1次快速 / 3次DoD标准 / 7次Gutmann标准）
- **零填充**：覆写为 0x00 后删除，防止数据雕刻恢复
- **删除前预览**：显示文件信息后确认删除

## 技术原理

### 文件雕刻 (File Carving)
当文件被删除时，文件系统仅移除索引条目（inode/dentry），实际数据块仍保留在存储介质上。本工具通过 `dd` 直接读取原始块设备（需 Root），扫描文件魔数（magic bytes）识别并重建已删除文件：

- **Header 匹配**：JPEG (`FF D8 FF`)、PNG (`89 50 4E 47...`)、MP4 (`ftyp` box) 等
- **Footer 定位**：通过文件尾精确确定文件大小（如 JPEG 的 `FF D9`）
- **容器解析**：MP4 解析 ISO Base Media ftyp box 大小；RIFF 解析 WebP/AVI/WAV
- **启发式估算**：无 footer 时按类型经验值估算

### SQLite 已删除记录恢复
SQLite 以固定大小页（默认 4096 字节）存储数据。删除记录时不会清零，而是：
1. 将页加入空闲页链表（freelist）
2. 在页内标记 freeblock
3. 修改 cell 指针数组

本工具直接解析 SQLite 文件格式，从以下区域扫描已删除记录：
- **空闲页链表**（freelist trunk/leaf pages）
- **页内未分配空间**（cell content area 到页尾）
- **页内 freeblock 链表**

通过验证 varint header、serial type 有效性来识别真实的已删除记录。

### 安全删除
1. `KeyguardManager.createConfirmDeviceCredentialIntent()` 验证锁屏密码
2. 以 `rws` 模式打开文件，分块覆写为 0
3. `fsync()` 强制写入物理介质
4. 截断文件长度为 0
5. 删除文件

## 环境要求

- Android 6.0+ (API 24+)
- 设备已获取 Root 权限
- Android Studio (用于编译) 或 Gradle 8.5+

## 编译构建

```bash
# 克隆项目后
./gradlew assembleDebug

# 产物位置
app/build/outputs/apk/debug/app-debug.apk
```

## 项目结构

```
app/src/main/java/com/recovery/app/
├── MainActivity.kt              # 主界面 (Jetpack Compose)
├── MainViewModel.kt             # 状态管理
├── model/
│   └── RecoverableItem.kt       # 数据模型
├── recovery/
│   ├── RecoveryEngine.kt        # 恢复引擎（整合调度）
│   ├── FileCarver.kt            # 文件雕刻引擎
│   ├── SQLiteRecovery.kt        # SQLite 已删除记录恢复
│   └── signatures/
│       ├── FileSignature.kt     # 文件签名定义
│       └── SignatureRegistry.kt # 签名库（20+ 文件类型）
├── secure/
│   ├── SecureDelete.kt          # 安全删除（覆写+删除）
│   └── CredentialVerifier.kt    # 锁屏密码验证
├── preview/
│   └── PreviewManager.kt        # 预览管理
└── util/
    └── RootShell.kt             # Root Shell 命令封装
```

## 免责声明

本工具仅供合法的数据恢复、取证分析和个人设备数据找回使用。使用本工具访问他人设备数据可能违反相关法律法规，请确保你拥有设备的合法访问权限。安全删除操作不可逆，请谨慎使用。
