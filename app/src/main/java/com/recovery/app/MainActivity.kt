package com.recovery.app

import android.content.Intent
import android.graphics.BitmapFactory
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.ActivityResultLauncher
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.recovery.app.model.*
import com.recovery.app.secure.CredentialVerifier

class MainActivity : ComponentActivity() {

    private lateinit var credentialLauncher: ActivityResultLauncher<Intent>
    private var pendingCallback: ((Boolean) -> Unit)? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        credentialLauncher = CredentialVerifier.createLauncher(activityResultRegistry) { success ->
            pendingCallback?.invoke(success)
            pendingCallback = null
        }

        setContent {
            MaterialTheme {
                RecoveryApp(
                    onVerifyCredential = { callback ->
                        pendingCallback = callback
                        val verifier = CredentialVerifier(this)
                        val launched = verifier.verify(credentialLauncher)
                        if (!launched) {
                            callback(true)
                            pendingCallback = null
                        }
                    }
                )
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun RecoveryApp(onVerifyCredential: ((Boolean) -> Unit) -> Unit = {}) {
    val viewModel: MainViewModel = viewModel()
    var selectedTab by remember { mutableIntStateOf(0) }

    LaunchedEffect(Unit) {
        viewModel.checkRoot()
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("数据还原大师", fontWeight = FontWeight.Bold) },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.primary,
                    titleContentColor = Color.White
                )
            )
        },
        bottomBar = {
            NavigationBar {
                NavigationBarItem(
                    icon = { Icon(Icons.Default.Restore, contentDescription = "还原") },
                    label = { Text("数据还原") },
                    selected = selectedTab == 0,
                    onClick = { selectedTab = 0 }
                )
                NavigationBarItem(
                    icon = { Icon(Icons.Default.DeleteSweep, contentDescription = "删除") },
                    label = { Text("安全删除") },
                    selected = selectedTab == 1,
                    onClick = { selectedTab = 1 }
                )
            }
        }
    ) { padding ->
        Box(modifier = Modifier.padding(padding)) {
            when (selectedTab) {
                0 -> RecoveryScreen(viewModel)
                1 -> SecureDeleteScreen(viewModel, onVerifyCredential)
            }
        }
    }
}

// ==================== 数据还原界面 ====================

// ==================== 格式化辅助 ====================

private fun formatSpeed(bytesPerSec: Long): String = when {
    bytesPerSec <= 0 -> "--"
    bytesPerSec < 1024 * 1024 -> "${"%.1f".format(bytesPerSec / 1024.0)} KB/s"
    else -> "${"%.2f".format(bytesPerSec / (1024.0 * 1024))} MB/s"
}

private fun formatEta(ms: Long): String = when {
    ms <= 0 -> "计算中..."
    ms < 1000 -> "<1秒"
    ms < 60_000 -> "${ms / 1000}秒"
    ms < 3600_000 -> "${ms / 60_000}分${(ms % 60_000) / 1000}秒"
    else -> "${ms / 3600_000}时${(ms % 3600_000) / 60_000}分"
}

@Composable
fun RecoveryScreen(viewModel: MainViewModel) {
    val rootState by viewModel.rootAvailable.collectAsState()
    val scanState by viewModel.scanState.collectAsState()
    val showTypes by viewModel.showTypes.collectAsState()
    val minConfidence by viewModel.minConfidence.collectAsState()
    val sortMode by viewModel.sortMode.collectAsState()
    val selectedIds by viewModel.selectedFileIds.collectAsState()
    val scanSettings by viewModel.scanSettings.collectAsState()

    val selectedTypes = remember {
        mutableStateMapOf(
            RecoveryType.IMAGE to true,
            RecoveryType.VIDEO to true,
            RecoveryType.SMS to true,
            RecoveryType.CALL_LOG to true
        )
    }

    var showSettings by remember { mutableStateOf(false) }
    var showLogs by remember { mutableStateOf(false) }
    val logs by viewModel.logs.collectAsState()
    var previewFile by remember { mutableStateOf<RecoverableFile?>(null) }
    var previewRecord by remember { mutableStateOf<RecoverableRecord?>(null) }
    var showExport by remember { mutableStateOf(false) }

    // 恢复目录（可编辑，持久化保存避免重组丢失）+ 恢复结果提示
    var recoveryDir by rememberSaveable { mutableStateOf(viewModel.defaultRecoveryDir) }
    var recoveryMessage by remember { mutableStateOf<String?>(null) }
    val lastRecoveryPaths by viewModel.lastRecoveryPaths.collectAsState()

    previewFile?.let { FilePreviewDialog(file = it, onDismiss = { previewFile = null }) }
    previewRecord?.let { RecordPreviewDialog(record = it, onDismiss = { previewRecord = null }) }

    if (showExport) {
        val json = viewModel.exportRecords()
        AlertDialog(
            onDismissRequest = { showExport = false },
            title = { Text("导出记录 (JSON)") },
            text = {
                OutlinedTextField(
                    value = json,
                    onValueChange = {},
                    modifier = Modifier.fillMaxWidth().height(240.dp),
                    readOnly = true
                )
            },
            confirmButton = { TextButton(onClick = { showExport = false }) { Text("关闭") } }
        )
    }

    Column(modifier = Modifier.fillMaxSize().padding(16.dp)) {
        // Root 状态
        rootState?.let { hasRoot ->
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(
                    containerColor = if (hasRoot) Color(0xFFE8F5E9) else Color(0xFFFFEBEE)
                )
            ) {
                Row(
                    modifier = Modifier.padding(12.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        if (hasRoot) Icons.Default.VerifiedUser else Icons.Default.Warning,
                        contentDescription = null,
                        tint = if (hasRoot) Color(0xFF2E7D32) else Color(0xFFC62828)
                    )
                    Spacer(Modifier.width(8.dp))
                    Text(
                        if (hasRoot) "已获取 Root 权限" else "未检测到 Root 权限",
                        fontSize = 14.sp
                    )
                }
            }
        }

        Spacer(Modifier.height(12.dp))

        // 扫描设置按钮行
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(
                onClick = { showSettings = true },
                modifier = Modifier.weight(1f)
            ) {
                Icon(Icons.Default.Settings, contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(Modifier.width(4.dp))
                Text("扫描设置")
            }
            OutlinedButton(
                onClick = { showLogs = !showLogs },
                modifier = Modifier.weight(1f)
            ) {
                Icon(Icons.Default.List, contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(Modifier.width(4.dp))
                Text("日志${if (logs.isNotEmpty()) "(${logs.size})" else ""}")
            }
            OutlinedButton(
                onClick = { showExport = true },
                modifier = Modifier.weight(1f),
                enabled = scanState.records.isNotEmpty()
            ) {
                Icon(Icons.Default.Share, contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(Modifier.width(4.dp))
                Text("导出记录")
            }
        }

        if (showSettings) {
            ScanSettingsDialog(
                settings = scanSettings,
                minConfidence = minConfidence,
                sortMode = sortMode,
                onDismiss = { showSettings = false },
                onSettingsChanged = { viewModel.updateSettings(it) },
                onConfidenceChanged = { viewModel.setMinConfidence(it) },
                onSortChanged = { viewModel.setSortMode(it) }
            )
        }

        // 类型选择
        Text("选择要恢复的数据类型", fontWeight = FontWeight.Bold, fontSize = 15.sp)
        Spacer(Modifier.height(6.dp))
        val typeLabels = mapOf(
            RecoveryType.IMAGE to "图片", RecoveryType.VIDEO to "视频",
            RecoveryType.AUDIO to "音频", RecoveryType.CALL_LOG to "通话记录",
            RecoveryType.SMS to "短信", RecoveryType.CONTACT to "联系人",
            RecoveryType.WHATSAPP to "WhatsApp"
        )
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(4.dp)) {
            typeLabels.forEach { (type, label) ->
                FilterChip(
                    selected = selectedTypes[type] == true,
                    onClick = { selectedTypes[type] = !(selectedTypes[type] ?: false) },
                    label = { Text(label, fontSize = 12.sp) }
                )
            }
        }

        Spacer(Modifier.height(10.dp))

        // 开始扫描按钮
        Button(
            onClick = {
                val types = selectedTypes.filter { it.value }.keys.toSet()
                if (types.isNotEmpty()) viewModel.startRecovery(types)
            },
            modifier = Modifier.fillMaxWidth(),
            enabled = !scanState.isScanning && rootState == true
        ) {
            if (scanState.isScanning) {
                CircularProgressIndicator(modifier = Modifier.size(20.dp), color = Color.White, strokeWidth = 2.dp)
                Spacer(Modifier.width(8.dp))
                Text("扫描中...")
            } else {
                Icon(Icons.Default.Search, contentDescription = null)
                Spacer(Modifier.width(8.dp))
                Text("开始扫描")
            }
        }

        // 进度条 + 进度文本
        if (scanState.isScanning || scanState.isCompleted) {
            Spacer(Modifier.height(10.dp))
            LinearProgressIndicator(
                progress = { scanState.progress },
                modifier = Modifier.fillMaxWidth().height(8.dp),
            )
            Spacer(Modifier.height(4.dp))
            Text(
                "${(scanState.progress * 100).toInt()}% · ${scanState.currentPhaseText}",
                fontSize = 12.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            // 实时速率 + 倒计时
            if (scanState.isScanning && scanState.totalBytes > 0) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text(
                        "速率: ${formatSpeed(scanState.speedBytesPerSec)}",
                        fontSize = 11.sp,
                        color = MaterialTheme.colorScheme.primary
                    )
                    Text(
                        "剩余: ${formatEta(scanState.etaMs)}",
                        fontSize = 11.sp,
                        color = MaterialTheme.colorScheme.primary
                    )
                }
            }
            // 实时统计
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Text("文件: ${scanState.filesFound}", fontSize = 12.sp, color = MaterialTheme.colorScheme.primary)
                Text("记录: ${scanState.recordsFound}", fontSize = 12.sp, color = MaterialTheme.colorScheme.primary)
            }
        }

        // 实时日志面板（可展开）
        if (showLogs) {
            Spacer(Modifier.height(10.dp))
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = Color(0xFF1E1E1E))
            ) {
                Column(modifier = Modifier.padding(8.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text("实时日志", color = Color.White, fontWeight = FontWeight.Medium, fontSize = 13.sp)
                        Text("${logs.size} 条", color = Color(0xFF9E9E9E), fontSize = 11.sp)
                    }
                    Spacer(Modifier.height(6.dp))
                    LazyColumn(
                        modifier = Modifier
                            .fillMaxWidth()
                            .heightIn(max = 240.dp)
                    ) {
                        items(logs) { entry ->
                            val color = when (entry.level) {
                                LogLevel.INFO -> Color(0xFF90CAF9)
                                LogLevel.WARN -> Color(0xFFFFE082)
                                LogLevel.ERROR -> Color(0xFFEF9A9A)
                                LogLevel.SUCCESS -> Color(0xFFA5D6A7)
                            }
                            val time = java.text.SimpleDateFormat("HH:mm:ss.SSS", java.util.Locale.US)
                                .format(java.util.Date(entry.timestamp))
                            Row(verticalAlignment = Alignment.Top) {
                                Text(time, color = Color(0xFF757575), fontSize = 10.sp,
                                    fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace)
                                Spacer(Modifier.width(6.dp))
                                Text(entry.message, color = color, fontSize = 12.sp,
                                    fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace)
                            }
                        }
                    }
                }
            }
        }

        Spacer(Modifier.height(12.dp))

        // 批量操作栏
        if (selectedIds.isNotEmpty()) {
            Column(modifier = Modifier.fillMaxWidth().padding(bottom = 8.dp)) {
                // 恢复目录输入
                OutlinedTextField(
                    value = recoveryDir,
                    onValueChange = { recoveryDir = it },
                    label = { Text("恢复到目录") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                    textStyle = androidx.compose.ui.text.TextStyle(fontSize = 12.sp)
                )
                Row(
                    modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text("已选 ${selectedIds.size} 项", fontSize = 13.sp, fontWeight = FontWeight.Medium)
                    Spacer(Modifier.weight(1f))
                    TextButton(onClick = {
                        recoveryMessage = null
                        viewModel.recoverSelected(recoveryDir) { paths ->
                            recoveryMessage = if (paths.isNotEmpty()) {
                                "已恢复 ${paths.size} 个文件到:\n${paths.joinToString("\n") { "  $it" }}"
                            } else "恢复失败"
                        }
                    }) {
                        Icon(Icons.Default.Save, contentDescription = null, modifier = Modifier.size(18.dp))
                        Spacer(Modifier.width(4.dp))
                        Text("批量恢复")
                    }
                    TextButton(onClick = { viewModel.selectAllFiles(false) }) {
                        Text("取消")
                    }
                }
                // 恢复结果提示
                recoveryMessage?.let { msg ->
                    Spacer(Modifier.height(4.dp))
                    Card(colors = CardDefaults.cardColors(containerColor = Color(0xFFE8F5E9))) {
                        Text(
                            msg,
                            modifier = Modifier.padding(8.dp),
                            fontSize = 11.sp,
                            color = Color(0xFF2E7D32)
                        )
                    }
                }
            }
        }

        // 结果列表
        val files = viewModel.getFilteredFiles()
        val records = scanState.records

        if (files.isEmpty() && records.isEmpty()) {
            if (scanState.isCompleted) {
                Text("未发现可恢复的数据", color = Color.Gray)
            }
        } else {
            LazyColumn(modifier = Modifier.fillMaxSize()) {
                // 统计头部
                item {
                    Row(
                        modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Text("扫描结果 (${files.size} 文件 / ${records.size} 记录)",
                            fontWeight = FontWeight.Bold, fontSize = 15.sp)
                    }
                }
                // 文件列表
                items(files, key = { it.id }) { file ->
                    FileItemView(
                        file = file,
                        selected = file.id in selectedIds,
                        onToggleSelect = { viewModel.toggleFileSelected(file.id) },
                        onClick = { previewFile = file }
                    )
                }
                // 记录列表
                items(records, key = { it.id }) { record ->
                    RecordItemView(record) { previewRecord = record }
                }
                item { Spacer(Modifier.height(80.dp)) }
            }
        }
    }
}

// ==================== 文件项视图（含缩略图 + 置信度 + 选择） ====================

@Composable
fun FileItemView(
    file: RecoverableFile,
    selected: Boolean,
    onToggleSelect: () -> Unit,
    onClick: () -> Unit
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 3.dp)
            .clickable { onClick() },
        colors = CardDefaults.cardColors(
            containerColor = if (selected) Color(0xFFE3F2FD) else MaterialTheme.colorScheme.surfaceVariant
        )
    ) {
        Row(
            modifier = Modifier.padding(10.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            // 缩略图 / 类型图标
            if (file.type == RecoveryType.IMAGE && file.thumbnail != null) {
                val bmp = remember(file.thumbnail) {
                    BitmapFactory.decodeByteArray(file.thumbnail, 0, file.thumbnail.size)
                }
                if (bmp != null) {
                    androidx.compose.foundation.Image(
                        bitmap = bmp.asImageBitmap(),
                        contentDescription = null,
                        modifier = Modifier
                            .size(56.dp)
                            .clip(RoundedCornerShape(6.dp)),
                        contentScale = ContentScale.Crop
                    )
                } else {
                    TypeIcon(file.type)
                }
            } else {
                TypeIcon(file.type)
            }

            Spacer(Modifier.width(12.dp))

            // 信息
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    "recovered_${file.id}.${file.extension}",
                    fontWeight = FontWeight.Medium,
                    fontSize = 14.sp,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Row(verticalAlignment = Alignment.CenterVertically) {
                    ConfidenceBadge(file.confidence)
                    Spacer(Modifier.width(6.dp))
                    Text("${formatFileSize(file.estimatedSize)}", fontSize = 11.sp, color = Color.Gray)
                }
            }

            // 选择框
            Checkbox(
                checked = selected,
                onCheckedChange = { onToggleSelect() }
            )
        }
    }
}

@Composable
fun TypeIcon(type: RecoveryType) {
    Box(
        modifier = Modifier
            .size(56.dp)
            .clip(RoundedCornerShape(6.dp))
            .background(MaterialTheme.colorScheme.primary.copy(alpha = 0.15f)),
        contentAlignment = Alignment.Center
    ) {
        Icon(
            when (type) {
                RecoveryType.IMAGE -> Icons.Default.Image
                RecoveryType.VIDEO -> Icons.Default.VideoLibrary
                RecoveryType.AUDIO -> Icons.Default.AudioFile
                else -> Icons.Default.Description
            },
            contentDescription = null,
            tint = MaterialTheme.colorScheme.primary,
            modifier = Modifier.size(28.dp)
        )
    }
}

@Composable
fun ConfidenceBadge(confidence: Confidence) {
    val (color, text) = when (confidence) {
        Confidence.HIGH -> Color(0xFF2E7D32) to "高"
        Confidence.MEDIUM -> Color(0xFFE65100) to "中"
        Confidence.LOW -> Color(0xFF757575) to "低"
    }
    Text(
        text,
        fontSize = 10.sp,
        color = Color.White,
        modifier = Modifier
            .background(color, RoundedCornerShape(4.dp))
            .padding(horizontal = 6.dp, vertical = 1.dp)
    )
}

// ==================== 记录项视图（按类型渲染） ====================

@Composable
fun RecordItemView(record: RecoverableRecord, onClick: () -> Unit = {}) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 3.dp)
            .clickable { onClick() },
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
    ) {
        Row(modifier = Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
            // 类型头像
            Box(
                modifier = Modifier
                    .size(44.dp)
                    .clip(RoundedCornerShape(22.dp))
                    .background(MaterialTheme.colorScheme.primary.copy(alpha = 0.15f)),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    when (record.type) {
                        RecoveryType.CALL_LOG -> Icons.Default.Call
                        RecoveryType.SMS -> Icons.Default.Sms
                        RecoveryType.CONTACT -> Icons.Default.Person
                        RecoveryType.WHATSAPP -> Icons.Default.Chat
                        else -> Icons.Default.Description
                    },
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary
                )
            }
            Spacer(Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
                when (record.type) {
                    RecoveryType.SMS -> {
                        Text(
                            record.fields["号码"] ?: "未知号码",
                            fontWeight = FontWeight.Medium, fontSize = 14.sp
                        )
                        Text(
                            record.fields["内容"] ?: "",
                            fontSize = 12.sp, color = Color.Gray,
                            maxLines = 1, overflow = TextOverflow.Ellipsis
                        )
                        record.fields["日期"]?.let {
                            Text(it, fontSize = 10.sp, color = Color(0xFF9E9E9E))
                        }
                    }
                    RecoveryType.CALL_LOG -> {
                        Text(
                            record.fields["号码"] ?: "未知号码",
                            fontWeight = FontWeight.Medium, fontSize = 14.sp
                        )
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text(record.fields["类型"] ?: "", fontSize = 12.sp, color = Color.Gray)
                            Spacer(Modifier.width(8.dp))
                            Text("${record.fields["时长(秒)"] ?: ""}s", fontSize = 12.sp, color = Color.Gray)
                        }
                        record.fields["日期"]?.let {
                            Text(it, fontSize = 10.sp, color = Color(0xFF9E9E9E))
                        }
                    }
                    RecoveryType.CONTACT -> {
                        Text(
                            record.fields["显示名"] ?: "未知联系人",
                            fontWeight = FontWeight.Medium, fontSize = 14.sp
                        )
                        Text(
                            record.fields["数据"] ?: "",
                            fontSize = 12.sp, color = Color.Gray,
                            maxLines = 1, overflow = TextOverflow.Ellipsis
                        )
                    }
                    else -> {
                        Text(record.type.name, fontWeight = FontWeight.Medium,
                            color = MaterialTheme.colorScheme.primary, fontSize = 14.sp)
                        record.fields.entries.take(2).forEach { (k, v) ->
                            if (v.isNotEmpty()) Text("$k: $v", fontSize = 12.sp, maxLines = 1)
                        }
                    }
                }
            }
        }
    }
}

// ==================== 预览对话框 ====================

@Composable
fun FilePreviewDialog(file: RecoverableFile, onDismiss: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("文件预览") },
        text = {
            Column {
                if (file.type == RecoveryType.IMAGE && file.thumbnail != null) {
                    val bmp = remember(file.thumbnail) {
                        BitmapFactory.decodeByteArray(file.thumbnail, 0, file.thumbnail.size)
                    }
                    if (bmp != null) {
                        androidx.compose.foundation.Image(
                            bitmap = bmp.asImageBitmap(),
                            contentDescription = null,
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(200.dp)
                                .clip(RoundedCornerShape(8.dp)),
                            contentScale = ContentScale.Fit
                        )
                        Spacer(Modifier.height(8.dp))
                    }
                }
                Text("文件名: recovered_${file.id}.${file.extension}", fontWeight = FontWeight.Medium)
                Spacer(Modifier.height(4.dp))
                Text("类型: ${file.mimeType}")
                Text("大小: ${formatFileSize(file.estimatedSize)}")
                Text("偏移: 0x${file.offset.toString(16)}")
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text("置信度: ")
                    ConfidenceBadge(file.confidence)
                }
                if (file.headerBytes.isNotEmpty()) {
                    Spacer(Modifier.height(8.dp))
                    Text("文件头 (hex):", fontWeight = FontWeight.Medium, fontSize = 12.sp)
                    Text(
                        file.headerBytes.take(32).joinToString(" ") { "%02X".format(it) },
                        fontSize = 10.sp,
                        fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace
                    )
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) { Text("关闭") }
        }
    )
}

@Composable
fun RecordPreviewDialog(record: RecoverableRecord, onDismiss: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("记录详情 - ${record.type.name}") },
        text = {
            Column {
                record.fields.forEach { (k, v) ->
                    if (v.isNotEmpty()) {
                        Text("$k: ", fontWeight = FontWeight.Bold)
                        Text(v, fontSize = 13.sp)
                        Spacer(Modifier.height(6.dp))
                    }
                }
                Spacer(Modifier.height(4.dp))
                Text("来源: ${record.source}", fontSize = 11.sp, color = Color.Gray)
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) { Text("关闭") }
        }
    )
}

// ==================== 扫描设置对话框 ====================

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ScanSettingsDialog(
    settings: ScanSettings,
    minConfidence: Confidence,
    sortMode: SortMode,
    onDismiss: () -> Unit,
    onSettingsChanged: (ScanSettings) -> Unit,
    onConfidenceChanged: (Confidence) -> Unit,
    onSortChanged: (SortMode) -> Unit
) {
    var mode by remember { mutableStateOf(settings.mode) }
    var rangeStart by remember { mutableStateOf(settings.rangeStartPercent) }
    var rangeEnd by remember { mutableStateOf(settings.rangeEndPercent) }
    var sampleMb by remember { mutableStateOf((settings.sampleBytes / (1024 * 1024)).toInt()) }
    var gapMb by remember { mutableStateOf((settings.gapBytes / (1024 * 1024)).toInt()) }
    var minSizeKb by remember { mutableIntStateOf(settings.minFileSizeKb) }
    var maxSizeMb by remember { mutableIntStateOf(settings.maxFileSizeMb) }
    var onlyHigh by remember { mutableStateOf(settings.onlyHighConfidence) }
    var dedupe by remember { mutableStateOf(settings.dedupeEnabled) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("扫描设置") },
        text = {
            Column {
                // 扫描模式
                Text("扫描模式", fontWeight = FontWeight.Bold)
                Row {
                    FilterChip(
                        selected = mode == ScanMode.QUICK,
                        onClick = { mode = ScanMode.QUICK },
                        label = { Text("快速(稀疏)") }
                    )
                    Spacer(Modifier.width(6.dp))
                    FilterChip(
                        selected = mode == ScanMode.DEEP,
                        onClick = { mode = ScanMode.DEEP },
                        label = { Text("深度(完整)") }
                    )
                    Spacer(Modifier.width(6.dp))
                    FilterChip(
                        selected = mode == ScanMode.RANGE,
                        onClick = { mode = ScanMode.RANGE },
                        label = { Text("范围(百分比)") }
                    )
                }
                Text(
                    when (mode) {
                        ScanMode.QUICK -> "快速：每读取一段采样数据后跳过一段，快速覆盖全分区"
                        ScanMode.DEEP -> "深度：顺序完整扫描整个分区，最全面"
                        ScanMode.RANGE -> "范围：仅扫描指定百分比区间"
                    },
                    fontSize = 11.sp, color = Color.Gray
                )

                // RANGE 模式参数
                if (mode == ScanMode.RANGE) {
                    Spacer(Modifier.height(8.dp))
                    Text("起始: ${rangeStart.toInt()}%", fontSize = 13.sp)
                    Slider(value = rangeStart, onValueChange = { rangeStart = it }, valueRange = 0f..99f)
                    Text("结束: ${rangeEnd.toInt()}%", fontSize = 13.sp)
                    Slider(value = rangeEnd, onValueChange = { rangeEnd = it }, valueRange = 1f..100f)
                }

                // QUICK 模式参数
                if (mode == ScanMode.QUICK) {
                    Spacer(Modifier.height(8.dp))
                    Text("采样大小: $sampleMb MB", fontSize = 13.sp)
                    Slider(value = sampleMb.toFloat(), onValueChange = { sampleMb = it.toInt() },
                        valueRange = 1f..32f, steps = 30)
                    Text("跳过大小: $gapMb MB", fontSize = 13.sp)
                    Slider(value = gapMb.toFloat(), onValueChange = { gapMb = it.toInt() },
                        valueRange = 4f..64f, steps = 29)
                    Text("覆盖率: ${"%.0f".format(sampleMb.toDouble() / (sampleMb + gapMb) * 100)}%",
                        fontSize = 11.sp, color = Color.Gray)
                }

                Spacer(Modifier.height(12.dp))
                Text("文件大小范围", fontWeight = FontWeight.Bold)
                Text("最小: $minSizeKb KB", fontSize = 13.sp)
                Slider(value = minSizeKb.toFloat(), onValueChange = { minSizeKb = it.toInt() },
                    valueRange = 1f..1024f, steps = 10)
                Text("最大: $maxSizeMb MB", fontSize = 13.sp)
                Slider(value = maxSizeMb.toFloat(), onValueChange = { maxSizeMb = it.toInt() },
                    valueRange = 1f..4096f, steps = 20)

                Spacer(Modifier.height(12.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(checked = onlyHigh, onCheckedChange = { onlyHigh = it })
                    Text("仅显示中/高置信度", fontSize = 13.sp)
                }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(checked = dedupe, onCheckedChange = { dedupe = it })
                    Text("启用去重", fontSize = 13.sp)
                }

                Spacer(Modifier.height(12.dp))
                Text("显示过滤", fontWeight = FontWeight.Bold)
                Text("最低置信度:", fontSize = 13.sp)
                Row {
                    Confidence.values().forEach { c ->
                        FilterChip(
                            selected = minConfidence == c,
                            onClick = { onConfidenceChanged(c) },
                            label = { Text(when (c) {
                                Confidence.HIGH -> "高"
                                Confidence.MEDIUM -> "中"
                                Confidence.LOW -> "全部"
                            }) }
                        )
                        Spacer(Modifier.width(4.dp))
                    }
                }

                Spacer(Modifier.height(12.dp))
                Text("排序方式", fontWeight = FontWeight.Bold)
                Row {
                    SortMode.values().forEach { s ->
                        FilterChip(
                            selected = sortMode == s,
                            onClick = { onSortChanged(s) },
                            label = { Text(when (s) {
                                SortMode.CONFIDENCE -> "置信度"
                                SortMode.SIZE_DESC -> "大小↓"
                                SortMode.SIZE_ASC -> "大小↑"
                                SortMode.TYPE -> "类型"
                            }) }
                        )
                        Spacer(Modifier.width(4.dp))
                    }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = {
                onSettingsChanged(
                    settings.copy(
                        mode = mode,
                        rangeStartPercent = rangeStart.coerceAtMost(rangeEnd),
                        rangeEndPercent = rangeEnd.coerceAtLeast(rangeStart),
                        sampleBytes = sampleMb.toLong() * 1024 * 1024,
                        gapBytes = gapMb.toLong() * 1024 * 1024,
                        minFileSizeKb = minSizeKb,
                        maxFileSizeMb = maxSizeMb,
                        onlyHighConfidence = onlyHigh,
                        dedupeEnabled = dedupe
                    )
                )
                onDismiss()
            }) { Text("应用") }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("取消") }
        }
    )
}

// ==================== 安全删除界面 ====================

@Composable
fun SecureDeleteScreen(
    viewModel: MainViewModel,
    onVerifyCredential: ((Boolean) -> Unit) -> Unit
) {
    var inputPath by remember { mutableStateOf("") }
    var passes by remember { mutableIntStateOf(3) }
    var showPreview by remember { mutableStateOf(false) }
    val isDeleting by viewModel.isDeleting.collectAsState()
    val deleteProgress by viewModel.deleteProgress.collectAsState()

    val previewInfo = remember(inputPath) {
        if (inputPath.isNotEmpty()) viewModel.getDeletePreview(inputPath) else null
    }

    Column(modifier = Modifier.fillMaxSize().padding(16.dp)) {
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = Color(0xFFFFF3E0))
        ) {
            Column(modifier = Modifier.padding(12.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Default.Security, contentDescription = null, tint = Color(0xFFE65100))
                    Spacer(Modifier.width(8.dp))
                    Text("安全删除", fontWeight = FontWeight.Bold)
                }
                Spacer(Modifier.height(4.dp))
                Text(
                    "此操作将覆写文件内容后删除，数据将无法恢复。\n需要验证锁屏密码后才能执行。",
                    fontSize = 13.sp
                )
            }
        }

        Spacer(Modifier.height(16.dp))

        Text("文件路径", fontWeight = FontWeight.Medium)
        Spacer(Modifier.height(4.dp))
        OutlinedTextField(
            value = inputPath,
            onValueChange = { inputPath = it },
            modifier = Modifier.fillMaxWidth(),
            placeholder = { Text("/sdcard/...") },
            singleLine = true
        )

        if (showPreview && previewInfo != null) {
            Spacer(Modifier.height(12.dp))
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
            ) {
                Column(modifier = Modifier.padding(12.dp)) {
                    Text("文件预览", fontWeight = FontWeight.Bold, fontSize = 15.sp)
                    Spacer(Modifier.height(8.dp))
                    previewInfo.details.forEach { (k, v) ->
                        Text("$k: $v", fontSize = 13.sp)
                    }
                    previewInfo.previewText?.let {
                        Spacer(Modifier.height(8.dp))
                        Text(it, fontSize = 12.sp, color = Color(0xFFE65100))
                    }
                }
            }
        }

        Spacer(Modifier.height(12.dp))

        OutlinedButton(
            onClick = { showPreview = !showPreview },
            modifier = Modifier.fillMaxWidth(),
            enabled = inputPath.isNotEmpty()
        ) {
            Icon(Icons.Default.Visibility, contentDescription = null)
            Spacer(Modifier.width(8.dp))
            Text(if (showPreview) "隐藏预览" else "预览文件")
        }

        Spacer(Modifier.height(12.dp))

        Text("覆写次数: $passes", fontWeight = FontWeight.Medium)
        Slider(
            value = passes.toFloat(),
            onValueChange = { passes = it.toInt() },
            valueRange = 1f..7f,
            steps = 5
        )
        Text("1次=快速  3次=DoD标准  7次=Gutmann标准", fontSize = 12.sp, color = Color.Gray)

        Spacer(Modifier.height(16.dp))

        Button(
            onClick = {
                if (inputPath.isNotEmpty()) {
                    onVerifyCredential { success ->
                        if (success) viewModel.secureDelete(inputPath, passes) {}
                    }
                }
            },
            modifier = Modifier.fillMaxWidth(),
            enabled = !isDeleting && inputPath.isNotEmpty(),
            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFE53935))
        ) {
            if (isDeleting) {
                CircularProgressIndicator(modifier = Modifier.size(20.dp), color = Color.White, strokeWidth = 2.dp)
                Spacer(Modifier.width(8.dp))
                Text("删除中...")
            } else {
                Icon(Icons.Default.DeleteSweep, contentDescription = null)
                Spacer(Modifier.width(8.dp))
                Text("验证密码并安全删除")
            }
        }

        if (deleteProgress.isNotEmpty()) {
            Spacer(Modifier.height(8.dp))
            Text(deleteProgress, color = if (deleteProgress.contains("成功")) Color(0xFF2E7D32) else Color(0xFFC62828))
        }
    }
}

private fun formatFileSize(bytes: Long): String = when {
    bytes < 1024 -> "$bytes B"
    bytes < 1024 * 1024 -> "${bytes / 1024} KB"
    bytes < 1024L * 1024 * 1024 -> "${"%.1f".format(bytes / (1024.0 * 1024))} MB"
    else -> "${"%.2f".format(bytes / (1024.0 * 1024 * 1024))} GB"
}
