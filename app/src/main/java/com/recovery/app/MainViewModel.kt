package com.recovery.app

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.recovery.app.model.Confidence
import com.recovery.app.model.LogEntry
import com.recovery.app.model.RecoverableFile
import com.recovery.app.model.RecoverableRecord
import com.recovery.app.model.RecoveryType
import com.recovery.app.model.ScanSettings
import com.recovery.app.model.ScanState
import com.recovery.app.preview.PreviewManager
import com.recovery.app.recovery.RecoveryEngine
import com.recovery.app.secure.SecureDelete
import com.recovery.app.util.RootShell
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/**
 * 排序方式
 */
enum class SortMode {
    CONFIDENCE,  // 按置信度
    SIZE_DESC,   // 大小降序
    SIZE_ASC,    // 大小升序
    TYPE         // 按类型
}

/**
 * 主 ViewModel
 */
class MainViewModel : ViewModel() {

    private val recoveryEngine = RecoveryEngine()
    private val previewManager = PreviewManager()

    // ===== 恢复状态（实时流） =====
    val scanState: StateFlow<ScanState> = recoveryEngine.scanState
    val logs: StateFlow<List<LogEntry>> = recoveryEngine.logs

    private val _rootAvailable = MutableStateFlow<Boolean?>(null)
    val rootAvailable: StateFlow<Boolean?> = _rootAvailable.asStateFlow()

    // ===== 扫描设置 =====
    private val _scanSettings = MutableStateFlow(ScanSettings())
    val scanSettings: StateFlow<ScanSettings> = _scanSettings.asStateFlow()

    // ===== 显示过滤 =====
    private val _showTypes = MutableStateFlow<Set<RecoveryType>>(RecoveryType.values().toSet())
    val showTypes: StateFlow<Set<RecoveryType>> = _showTypes.asStateFlow()

    private val _minConfidence = MutableStateFlow(Confidence.LOW)
    val minConfidence: StateFlow<Confidence> = _minConfidence.asStateFlow()

    private val _sortMode = MutableStateFlow(SortMode.CONFIDENCE)
    val sortMode: StateFlow<SortMode> = _sortMode.asStateFlow()

    // ===== 选择 =====
    private val _selectedFileIds = MutableStateFlow<Set<Long>>(emptySet())
    val selectedFileIds: StateFlow<Set<Long>> = _selectedFileIds.asStateFlow()

    // ===== 安全删除状态 =====
    private val _isDeleting = MutableStateFlow(false)
    val isDeleting: StateFlow<Boolean> = _isDeleting.asStateFlow()

    private val _deleteProgress = MutableStateFlow("")
    val deleteProgress: StateFlow<String> = _deleteProgress.asStateFlow()

    /** 检查 Root 权限 */
    fun checkRoot() {
        viewModelScope.launch {
            _rootAvailable.value = RootShell.isRootAvailable()
        }
    }

    /** 更新扫描设置 */
    fun updateSettings(settings: ScanSettings) {
        _scanSettings.value = settings
    }

    /** 设置显示类型过滤 */
    fun setShowTypes(types: Set<RecoveryType>) {
        _showTypes.value = types
    }

    /** 设置最低置信度 */
    fun setMinConfidence(confidence: Confidence) {
        _minConfidence.value = confidence
    }

    /** 设置排序方式 */
    fun setSortMode(mode: SortMode) {
        _sortMode.value = mode
    }

    /** 切换文件选中 */
    fun toggleFileSelected(id: Long) {
        _selectedFileIds.value = _selectedFileIds.value.toMutableSet().apply {
            if (!add(id)) remove(id)
        }
    }

    /** 全选/取消全选 */
    fun selectAllFiles(select: Boolean) {
        val allIds = scanState.value.files.map { it.id }.toSet()
        _selectedFileIds.value = if (select) allIds else emptySet()
    }

    /**
     * 启动恢复扫描（实时流式）
     */
    fun startRecovery(types: Set<RecoveryType>) {
        viewModelScope.launch {
            recoveryEngine.recover(types, _scanSettings.value)
        }
    }

    /**
     * 恢复单个文件
     */
    fun recoverFile(item: RecoverableFile, outputDir: String, onDone: (String?) -> Unit) {
        viewModelScope.launch {
            val path = recoveryEngine.recoverFile(item, outputDir)
            onDone(path)
        }
    }

    /**
     * 批量恢复选中的文件
     */
    fun recoverSelected(outputDir: String, onDone: (Int) -> Unit) {
        viewModelScope.launch {
            val selected = scanState.value.files.filter { it.id in _selectedFileIds.value }
            val paths = recoveryEngine.recoverFiles(selected, outputDir)
            onDone(paths.size)
            _selectedFileIds.value = emptySet()
        }
    }

    /**
     * 导出记录为 JSON
     */
    fun exportRecords(): String {
        return recoveryEngine.exportRecordsJson(scanState.value.records)
    }

    /**
     * 安全删除文件
     */
    fun secureDelete(path: String, passes: Int = 3, onDone: (Boolean) -> Unit) {
        viewModelScope.launch {
            _isDeleting.value = true
            _deleteProgress.value = "正在安全删除..."
            val success = SecureDelete.deleteFile(path, passes)
            _isDeleting.value = false
            _deleteProgress.value = if (success) "删除成功" else "删除失败"
            onDone(success)
        }
    }

    /** 获取文件预览信息 */
    suspend fun getFilePreview(item: RecoverableFile) = previewManager.previewFile(item)

    /** 获取记录预览信息 */
    fun getRecordPreview(record: RecoverableRecord) = previewManager.previewRecord(record)

    /** 获取待删除文件预览 */
    fun getDeletePreview(path: String) = previewManager.previewFileForDelete(path)

    /**
     * 获取过滤并排序后的文件列表
     */
    fun getFilteredFiles(): List<RecoverableFile> {
        val state = scanState.value
        val types = _showTypes.value
        val minConf = _minConfidence.value
        var list = state.files.filter { it.type in types && confidenceRank(it.confidence) >= confidenceRank(minConf) }
        list = when (_sortMode.value) {
            SortMode.CONFIDENCE -> list.sortedByDescending { confidenceRank(it.confidence) }
            SortMode.SIZE_DESC -> list.sortedByDescending { it.estimatedSize }
            SortMode.SIZE_ASC -> list.sortedBy { it.estimatedSize }
            SortMode.TYPE -> list.sortedBy { it.type.name }
        }
        return list
    }

    private fun confidenceRank(c: Confidence): Int = when (c) {
        Confidence.HIGH -> 3
        Confidence.MEDIUM -> 2
        Confidence.LOW -> 1
    }
}
