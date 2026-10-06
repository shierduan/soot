package com.recovery.app

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.ActivityResultLauncher
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.recovery.app.model.RecoverableFile
import com.recovery.app.model.RecoverableRecord
import com.recovery.app.model.RecoveryType
import com.recovery.app.secure.CredentialVerifier
import kotlinx.coroutines.launch

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
                            // 设备无锁屏，直接通过
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

@Composable
fun RecoveryScreen(viewModel: MainViewModel) {
    val rootState by viewModel.rootAvailable.collectAsState()
    val isScanning by viewModel.isScanning.collectAsState()
    val scanProgress by viewModel.scanProgress.collectAsState()
    val result by viewModel.recoveryResult.collectAsState()

    val selectedTypes = remember {
        mutableStateMapOf(
            RecoveryType.IMAGE to true,
            RecoveryType.VIDEO to true,
            RecoveryType.SMS to true,
            RecoveryType.CALL_LOG to true
        )
    }

    var previewFile by remember { mutableStateOf<RecoverableFile?>(null) }
    var previewRecord by remember { mutableStateOf<RecoverableRecord?>(null) }
    val scope = rememberCoroutineScope()

    // 预览对话框
    previewFile?.let { file ->
        FilePreviewDialog(file = file, onDismiss = { previewFile = null }) {
            scope.launch {
                val info = viewModel.getFilePreview(file)
                // 这里可以展示更详细的预览
            }
        }
    }
    previewRecord?.let { record ->
        RecordPreviewDialog(record = record, onDismiss = { previewRecord = null })
    }

    Column(modifier = Modifier.fillMaxSize().padding(16.dp)) {
        // Root 状态提示
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
                        if (hasRoot) "已获取 Root 权限，可以恢复全部数据"
                        else "未检测到 Root 权限，部分功能不可用",
                        fontSize = 14.sp
                    )
                }
            }
        }

        Spacer(Modifier.height(12.dp))

        // 类型选择
        Text("选择要恢复的数据类型", fontWeight = FontWeight.Bold, fontSize = 16.sp)
        Spacer(Modifier.height(8.dp))

        val typeLabels = mapOf(
            RecoveryType.IMAGE to "图片",
            RecoveryType.VIDEO to "视频",
            RecoveryType.AUDIO to "音频",
            RecoveryType.CALL_LOG to "通话记录",
            RecoveryType.SMS to "短信",
            RecoveryType.CONTACT to "联系人",
            RecoveryType.WHATSAPP to "WhatsApp"
        )

        typeLabels.forEach { (type, label) ->
            Row(
                modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Checkbox(
                    checked = selectedTypes[type] == true,
                    onCheckedChange = { selectedTypes[type] = it }
                )
                Text(label, fontSize = 15.sp)
            }
        }

        Spacer(Modifier.height(12.dp))

        // 开始扫描按钮
        Button(
            onClick = {
                val types = selectedTypes.filter { it.value }.keys.toSet()
                if (types.isNotEmpty()) {
                    viewModel.startRecovery(types)
                }
            },
            modifier = Modifier.fillMaxWidth(),
            enabled = !isScanning && rootState == true
        ) {
            if (isScanning) {
                CircularProgressIndicator(
                    modifier = Modifier.size(20.dp),
                    color = Color.White,
                    strokeWidth = 2.dp
                )
                Spacer(Modifier.width(8.dp))
                Text("扫描中...")
            } else {
                Icon(Icons.Default.Search, contentDescription = null)
                Spacer(Modifier.width(8.dp))
                Text("开始扫描")
            }
        }

        if (scanProgress.isNotEmpty()) {
            Spacer(Modifier.height(8.dp))
            Text(scanProgress, fontSize = 13.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }

        Spacer(Modifier.height(16.dp))

        // 扫描结果
        result?.let { r ->
            if (r.files.isNotEmpty() || r.records.isNotEmpty()) {
                Text("扫描结果", fontWeight = FontWeight.Bold, fontSize = 16.sp)
                Spacer(Modifier.height(8.dp))

                LazyColumn(modifier = Modifier.fillMaxSize()) {
                    items(r.files) { file ->
                        FileItemView(file) { previewFile = file }
                    }
                    items(r.records) { record ->
                        RecordItemView(record) { previewRecord = record }
                    }
                }
            } else if (!isScanning) {
                Text("未发现可恢复的数据", color = Color.Gray)
            }
        }
    }
}

@Composable
fun FileItemView(file: RecoverableFile, onClick: () -> Unit = {}) {
    Card(
        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
    ) {
        Row(modifier = Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
            Icon(
                when (file.type) {
                    RecoveryType.IMAGE -> Icons.Default.Image
                    RecoveryType.VIDEO -> Icons.Default.VideoLibrary
                    RecoveryType.AUDIO -> Icons.Default.AudioFile
                    else -> Icons.Default.Description
                },
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary
            )
            Spacer(Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text("recovered_${file.id}.${file.extension}", fontWeight = FontWeight.Medium)
                Text(
                    "${formatFileSize(file.estimatedSize)} · ${file.mimeType}",
                    fontSize = 12.sp,
                    color = Color.Gray
                )
            }
            TextButton(onClick = onClick) {
                Text("预览")
            }
        }
    }
}

@Composable
fun RecordItemView(record: RecoverableRecord, onClick: () -> Unit = {}) {
    Card(
        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
    ) {
        Row(
            modifier = Modifier.padding(12.dp).fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    record.type.name,
                    fontWeight = FontWeight.Medium,
                    color = MaterialTheme.colorScheme.primary
                )
                Spacer(Modifier.height(4.dp))
                record.fields.entries.take(3).forEach { (k, v) ->
                    if (v.isNotEmpty()) {
                        Text("$k: $v", fontSize = 13.sp, maxLines = 1)
                    }
                }
            }
            TextButton(onClick = onClick) {
                Text("详情")
            }
        }
    }
}

// ==================== 预览对话框 ====================

@Composable
fun FilePreviewDialog(file: RecoverableFile, onDismiss: () -> Unit, onLoad: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("文件预览") },
        text = {
            Column {
                Text("文件名: recovered_${file.id}.${file.extension}", fontWeight = FontWeight.Medium)
                Spacer(Modifier.height(8.dp))
                Text("类型: ${file.mimeType}")
                Text("大小: ${formatFileSize(file.estimatedSize)}")
                Text("偏移: 0x${file.offset.toString(16)}")
                Spacer(Modifier.height(8.dp))
                if (file.headerBytes.isNotEmpty()) {
                    Text("文件头 (hex):", fontWeight = FontWeight.Medium)
                    Spacer(Modifier.height(4.dp))
                    Text(
                        file.headerBytes.take(32).joinToString(" ") { "%02X".format(it) },
                        fontSize = 11.sp,
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

        // 预览区域
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

        // 预览按钮
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
                    // 先验证锁屏密码，再执行删除
                    onVerifyCredential { success ->
                        if (success) {
                            viewModel.secureDelete(inputPath, passes) {}
                        }
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

private fun formatFileSize(bytes: Long): String {
    return when {
        bytes < 1024 -> "$bytes B"
        bytes < 1024 * 1024 -> "${bytes / 1024} KB"
        bytes < 1024 * 1024 * 1024 -> "${"%.1f".format(bytes / (1024.0 * 1024))} MB"
        else -> "${"%.2f".format(bytes / (1024.0 * 1024 * 1024))} GB"
    }
}
